// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Enum } from "@safe-global/libraries/Enum.sol";

/**
 * @title IGuard
 * @notice Interface for Safe transaction guards
 */
interface IGuard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

/**
 * @title WhitelistGuard
 * @author OTC Trust
 * @notice A Safe guard that restricts transactions to whitelisted addresses only.
 *         Designed for use with native Safe UI - no special tools required.
 *
 * USE CASE:
 *   - Executor uses Safe UI to send funds to whitelisted addresses
 *   - Executor CANNOT change Safe settings (guard, modules, owners)
 *   - Recovery signers manage whitelist and can recover funds if executor loses key
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                         GNOSIS SAFE                             │
 * │  Owner: Executor (threshold 1)                                  │
 * │                                                                 │
 * │  ┌───────────────────────────────────────────────────────────┐ │
 * │  │  WHITELIST GUARD                                          │ │
 * │  │  ✓ Allows sends to whitelisted addresses                  │ │
 * │  │  ✗ Blocks admin functions (setGuard, enableModule, etc)   │ │
 * │  │  ✗ Blocks delegatecall                                    │ │
 * │  └───────────────────────────────────────────────────────────┘ │
 * │                                                                 │
 * │  ┌───────────────────────────────────────────────────────────┐ │
 * │  │  ZODIAC ROLES MODIFIER (for Recovery)                     │ │
 * │  │  • Recovery signers have "Admin" role                     │ │
 * │  │  • Can manage whitelist                                   │ │
 * │  │  • Can enable bypass for emergency recovery               │ │
 * │  └───────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * KEY INSIGHT: Module transactions bypass the guard!
 * So recovery signers execute through the Roles Modifier (a module),
 * while the executor uses the normal Safe UI (goes through guard).
 */
contract WhitelistGuard is IGuard {
    // ============ Constants ============

    // Safe admin function selectors - all blocked for regular transactions
    bytes4 private constant SET_GUARD = 0xe19a9dd9;
    bytes4 private constant ENABLE_MODULE = 0x610b5925;
    bytes4 private constant DISABLE_MODULE = 0xe009cfde;
    bytes4 private constant ADD_OWNER = 0x0d582f13;
    bytes4 private constant REMOVE_OWNER = 0xf8dc5dd9;
    bytes4 private constant SWAP_OWNER = 0xe318b52b;
    bytes4 private constant CHANGE_THRESHOLD = 0x694e80c3;
    bytes4 private constant SET_FALLBACK = 0xf08a0323;

    // ============ State Variables ============

    /// @notice The Safe this guard protects
    address public immutable safe;

    /// @notice Admin address (typically Zodiac Roles Modifier)
    address public admin;

    /// @notice Whitelisted destination addresses
    mapping(address => bool) public whitelist;

    /// @notice Count of whitelisted addresses
    uint256 public whitelistCount;

    /// @notice Emergency bypass - when true, executor can send anywhere
    bool public bypassEnabled;

    /// @notice When true, admin address cannot be changed
    bool public adminLocked;

    // ============ Events ============

    event AddressWhitelisted(address indexed addr);
    event AddressRemoved(address indexed addr);
    event BypassToggled(bool enabled);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event AdminLocked();

    // ============ Errors ============

    error OnlyAdmin();
    error NotWhitelisted(address to);
    error DelegateCallBlocked();
    error AdminFunctionBlocked(bytes4 selector);
    error ZeroAddress();
    error AlreadyWhitelisted(address addr);
    error NotInWhitelist(address addr);
    error AdminIsLocked();

    // ============ Modifiers ============

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    // ============ Constructor ============

    /**
     * @notice Deploy the WhitelistGuard
     * @param _safe Address of the Safe to protect
     * @param _admin Admin address (Zodiac Roles Modifier for recovery signers)
     * @param _whitelist Initial list of whitelisted addresses
     */
    constructor(address _safe, address _admin, address[] memory _whitelist) {
        if (_safe == address(0) || _admin == address(0)) revert ZeroAddress();

        safe = _safe;
        admin = _admin;

        for (uint256 i = 0; i < _whitelist.length; i++) {
            if (_whitelist[i] != address(0) && !whitelist[_whitelist[i]]) {
                whitelist[_whitelist[i]] = true;
                whitelistCount++;
                emit AddressWhitelisted(_whitelist[i]);
            }
        }
    }

    // ============ Admin Functions ============

    /// @notice Add address to whitelist
    function addToWhitelist(address addr) external onlyAdmin {
        if (addr == address(0)) revert ZeroAddress();
        if (whitelist[addr]) revert AlreadyWhitelisted(addr);
        whitelist[addr] = true;
        whitelistCount++;
        emit AddressWhitelisted(addr);
    }

    /// @notice Remove address from whitelist
    function removeFromWhitelist(address addr) external onlyAdmin {
        if (!whitelist[addr]) revert NotInWhitelist(addr);
        whitelist[addr] = false;
        whitelistCount--;
        emit AddressRemoved(addr);
    }

    /// @notice Add multiple addresses to whitelist
    function addBatch(address[] calldata addrs) external onlyAdmin {
        for (uint256 i = 0; i < addrs.length; i++) {
            if (addrs[i] != address(0) && !whitelist[addrs[i]]) {
                whitelist[addrs[i]] = true;
                whitelistCount++;
                emit AddressWhitelisted(addrs[i]);
            }
        }
    }

    /// @notice Enable/disable emergency bypass (allows sending anywhere)
    function setBypass(bool enabled) external onlyAdmin {
        bypassEnabled = enabled;
        emit BypassToggled(enabled);
    }

    /// @notice Change admin address
    function setAdmin(address newAdmin) external onlyAdmin {
        if (adminLocked) revert AdminIsLocked();
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminChanged(admin, newAdmin);
        admin = newAdmin;
    }

    /// @notice Permanently lock admin (cannot be changed after this)
    function lockAdmin() external onlyAdmin {
        adminLocked = true;
        emit AdminLocked();
    }

    // ============ Guard Interface ============

    /**
     * @notice Called before every Safe transaction
     * @dev Enforces whitelist and blocks admin functions
     */
    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external override {
        // 1. Always block delegatecall
        if (operation == Enum.Operation.DelegateCall) {
            revert DelegateCallBlocked();
        }

        // 2. Block admin functions on the Safe
        if (to == safe && data.length >= 4) {
            bytes4 selector = bytes4(data);
            if (
                selector == SET_GUARD ||
                selector == ENABLE_MODULE ||
                selector == DISABLE_MODULE ||
                selector == ADD_OWNER ||
                selector == REMOVE_OWNER ||
                selector == SWAP_OWNER ||
                selector == CHANGE_THRESHOLD ||
                selector == SET_FALLBACK
            ) {
                revert AdminFunctionBlocked(selector);
            }
        }

        // 3. Allow calls to the guard itself
        if (to == address(this)) return;

        // 4. If bypass enabled, allow everything
        if (bypassEnabled) return;

        // 5. Check whitelist
        if (!whitelist[to]) {
            revert NotWhitelisted(to);
        }
    }

    /// @notice Called after transaction execution (not used)
    function checkAfterExecution(bytes32, bool) external override {}

    // ============ View Functions ============

    function isWhitelisted(address addr) external view returns (bool) {
        return whitelist[addr];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IGuard).interfaceId;
    }
}

