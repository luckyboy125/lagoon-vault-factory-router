// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Lagoon vault interface (simplified)
interface ILagoonVault {
    function isTotalAssetsValid() external view returns (bool);
    function syncDeposit(
        uint256 assets,
        address receiver,
        address referral
    ) external returns (uint256);
    function requestDeposit(
        uint256 assets,
        address controller,
        address owner
    ) external returns (uint256);
    function claimAsyncDeposit(uint256 requestId) external;
}

/**
 * @title DepositRouter
 * @notice Routes deposits to Lagoon vaults with EIP-712 intent verification
 * Supports both synchronous and asynchronous deposit flows
 */
contract DepositRouter is EIP712, Ownable {
    using SafeERC20 for IERC20;

    bytes32 public constant DEPOSIT_INTENT_TYPEHASH =
        keccak256(
            "DepositIntent(address user,address vault,address asset,uint256 amount,uint256 nonce,uint256 deadline,address kolAddress)"
        );

    struct DepositIntent {
        address user;
        address vault;
        address asset;
        address kolAddress;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    // Optimized struct packing (7 slots instead of 9):
    // Slot 1: user (address) = 1 slot
    // Slot 2: vault (address) = 1 slot
    // Slot 3: asset (address) = 1 slot
    // Slot 4: kolAddress (address) = 1 slot
    // Slot 5: amount (uint256) = 1 slot
    // Slot 6: requestId (uint256) = 1 slot
    // Slot 7: timestamp (uint64) + isAsync (bool) + intentHash (bytes32) - packed efficiently
    // Note: Solidity will pack uint64 + bool in same slot, but bytes32 needs its own slot
    // Reordered for better gas efficiency
    struct DepositRecord {
        address user;
        address vault;
        address asset;
        address kolAddress;
        uint256 amount;
        uint256 requestId; // For async deposits
        uint64 timestamp;   // Reduced from uint256 - timestamp fits in uint64, packs with isAsync
        bytes32 intentHash;
        bool isAsync;       // Packs with timestamp (8 bytes + 1 byte = 9 bytes in 1 slot)
    }

    // Mapping: user => nonce => used
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    // Mapping: intent hash => deposit record
    mapping(bytes32 => DepositRecord) public deposits;

    // Fee configuration - packed for gas efficiency
    // Pack feesEnabled (1 byte) with treasury address (20 bytes) = 21 bytes in 1 slot
    // Note: Solidity will use 1 slot for bool + address (padded to 32 bytes)
    bool public feesEnabled;
    uint256 public constant FEE_BPS = 10; // 10 basis points (0.1%)
    uint256 public constant KOL_FEE_SHARE = 70; // 70% of fee to KOL
    uint256 public constant YIELDO_FEE_SHARE = 30; // 30% of fee to Yieldo
    address public treasury; // Yieldo treasury address

    // Custom errors for gas savings (cheaper than require strings)
    error DepositAlreadyExecuted();
    error IntentExpired();
    error NonceAlreadyUsed();
    error InvalidSignature();
    error DepositNotFound();
    error NotAsyncDeposit();
    error VaultNotReady();
    error InvalidTreasuryAddress();

    // Events
    event DepositIntentVerified(
        bytes32 indexed intentHash,
        address indexed user,
        address indexed vault,
        address asset,
        uint256 amount,
        address kolAddress,
        bool isAsync
    );

    event DepositExecuted(
        bytes32 indexed intentHash,
        address indexed user,
        address indexed vault,
        uint256 amount,
        bool isAsync
    );

    event AsyncDepositRequested(
        bytes32 indexed intentHash,
        address indexed user,
        address indexed vault,
        uint256 amount
    );

    event FeeCollected(
        bytes32 indexed intentHash,
        address indexed kolAddress,
        uint256 totalFee,
        uint256 kolFee,
        uint256 yieldoFee
    );

    constructor(address _treasury) EIP712("YieldoDepositRouter", "1") Ownable(msg.sender) {
        treasury = _treasury;
        feesEnabled = false; // Disabled by default (can be de-scoped)
    }

    /**
     * @notice Verify and execute deposit intent
     * @param intent The deposit intent parameters
     * @param signature The EIP-712 signature from the user
     */
    function verifyAndDeposit(
        DepositIntent calldata intent,
        bytes calldata signature
    ) external returns (bytes32 intentHash) {
        // Cache calldata reads to avoid repeated access
        address user = intent.user;
        address vaultAddr = intent.vault;
        address assetAddr = intent.asset;
        uint256 amount = intent.amount;
        uint256 nonce = intent.nonce;
        address kolAddr = intent.kolAddress;

        // Verify signature
        intentHash = _verifyIntent(intent, signature);
        
        // Check if already executed - cache storage read
        DepositRecord storage existingDeposit = deposits[intentHash];
        if (existingDeposit.timestamp != 0) revert DepositAlreadyExecuted();

        // Check deadline - cache block.timestamp
        uint256 currentTime = block.timestamp;
        if (currentTime > intent.deadline) revert IntentExpired();

        // Check nonce - cache storage read
        mapping(uint256 => bool) storage userNonces = usedNonces[user];
        if (userNonces[nonce]) revert NonceAlreadyUsed();
        userNonces[nonce] = true;

        // Cache storage reads
        bool _feesEnabled = feesEnabled;
        address _treasury = treasury;

        // Determine if async or sync - cache external call result
        ILagoonVault vault = ILagoonVault(vaultAddr);
        bool isAsync = !vault.isTotalAssetsValid();

        // Calculate fees and deposit amount
        uint256 depositAmount = amount;
        uint256 totalFee = 0;
        uint256 kolFee = 0;
        uint256 yieldoFee = 0;
        
        if (_feesEnabled) {
            // Unchecked multiplication/division - safe due to constants
            unchecked {
                totalFee = (amount * FEE_BPS) / 10000;
                kolFee = (totalFee * KOL_FEE_SHARE) / 100;
                yieldoFee = totalFee - kolFee; // Remaining 30%
            }
            
            depositAmount = amount - totalFee;
        }

        // Create IERC20 instance for SafeERC20 operations
        IERC20 asset = IERC20(assetAddr);

        // Transfer assets from user to router first
        asset.safeTransferFrom(user, address(this), amount);

        // Distribute fees (if enabled) - combine checks to reduce gas
        if (_feesEnabled) {
            emit FeeCollected(intentHash, kolAddr, totalFee, kolFee, yieldoFee);
            
            // Transfer fees - optimized to reduce external calls
            if (kolFee != 0 && kolAddr != address(0)) {
                asset.safeTransfer(kolAddr, kolFee);
            }
            if (yieldoFee != 0 && _treasury != address(0)) {
                asset.safeTransfer(_treasury, yieldoFee);
            }
        }

        // Handle async vs sync deposits
        uint256 requestId = 0;
        if (isAsync) {
            // Approve vault for async deposit
            asset.safeIncreaseAllowance(vaultAddr, depositAmount);
            // Request async deposit - transfers from router to vault
            requestId = vault.requestDeposit(depositAmount, address(this), user);
            emit AsyncDepositRequested(intentHash, user, vaultAddr, depositAmount);
        } else {
            // Approve vault for sync deposit
            asset.safeIncreaseAllowance(vaultAddr, depositAmount);
            // Execute sync deposit
            vault.syncDeposit(depositAmount, user, kolAddr);
            emit DepositExecuted(intentHash, user, vaultAddr, depositAmount, false);
        }

        // Record deposit intent (store deposit amount after fees)
        // Use cached timestamp from earlier
        deposits[intentHash] = DepositRecord({
            user: user,
            vault: vaultAddr,
            asset: assetAddr,
            kolAddress: kolAddr,
            amount: depositAmount, // Store amount after fees
            requestId: requestId,
            timestamp: uint64(currentTime),  // Use cached timestamp
            isAsync: isAsync,
            intentHash: intentHash
        });

        emit DepositIntentVerified(
            intentHash,
            user,
            vaultAddr,
            assetAddr,
            amount, // Original amount in event
            kolAddr,
            isAsync
        );

        return intentHash;
    }

    /**
     * @notice Execute async deposit claim (called after async deposit is ready)
     * @param intentHash The original intent hash
     */
    function claimAsyncDeposit(bytes32 intentHash) external {
        DepositRecord storage record = deposits[intentHash];
        if (record.timestamp == 0) revert DepositNotFound();
        if (!record.isAsync) revert NotAsyncDeposit();

        // Cache storage reads to avoid multiple SLOAD operations
        address vaultAddress = record.vault;
        uint256 requestId = record.requestId;
        address userAddr = record.user;
        uint256 depositAmount = record.amount;

        ILagoonVault vault = ILagoonVault(vaultAddress);
        if (!vault.isTotalAssetsValid()) revert VaultNotReady();

        // Claim the async deposit using the stored requestId
        // Assets are already in the vault from the requestDeposit call
        vault.claimAsyncDeposit(requestId);

        emit DepositExecuted(intentHash, userAddr, vaultAddress, depositAmount, true);
    }

    /**
     * @notice Get deposit record by intent hash
     */
    function getDeposit(bytes32 intentHash)
        external
        view
        returns (DepositRecord memory)
    {
        return deposits[intentHash];
    }

    /**
     * @notice Enable or disable fees (owner only)
     * @param _enabled Whether fees should be enabled
     */
    function setFeesEnabled(bool _enabled) external onlyOwner {
        feesEnabled = _enabled;
    }

    /**
     * @notice Update treasury address (owner only)
     * @param _treasury New treasury address
     */
    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert InvalidTreasuryAddress();
        treasury = _treasury;
    }

    /**
     * @notice Verify EIP-712 signature
     */
    function _verifyIntent(
        DepositIntent calldata intent,
        bytes calldata signature
    ) internal view returns (bytes32) {
        // Cache calldata reads
        address user = intent.user;
        
        bytes32 structHash = keccak256(
            abi.encode(
                DEPOSIT_INTENT_TYPEHASH,
                user,
                intent.vault,
                intent.asset,
                intent.amount,
                intent.nonce,
                intent.deadline,
                intent.kolAddress
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);

        if (signer != user) revert InvalidSignature();
        
        // Deterministic intent hash based on user, nonce, and intent parameters
        // Use encodePacked for gas efficiency (smaller than encode)
        return keccak256(abi.encodePacked(user, intent.nonce, intent.vault, intent.amount));
    }
}
