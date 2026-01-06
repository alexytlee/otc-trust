// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { WhitelistGuard } from "../src/WhitelistGuard.sol";
import { Enum } from "@safe-global/libraries/Enum.sol";

/**
 * @title WhitelistGuardTest
 * @notice Comprehensive security tests for WhitelistGuard
 */
contract WhitelistGuardTest is Test {
    WhitelistGuard public guard;

    address public safe = address(0x5AFE);
    address public admin = address(0xAD111);
    address public executor = address(0x7777);
    address public whitelisted1 = address(0x1111);
    address public whitelisted2 = address(0x2222);
    address public notWhitelisted = address(0x9999);
    address public attacker = address(0xBAD);

    // Safe function selectors
    bytes4 constant SET_GUARD = 0xe19a9dd9;
    bytes4 constant ENABLE_MODULE = 0x610b5925;
    bytes4 constant DISABLE_MODULE = 0xe009cfde;
    bytes4 constant ADD_OWNER = 0x0d582f13;
    bytes4 constant REMOVE_OWNER = 0xf8dc5dd9;
    bytes4 constant SWAP_OWNER = 0xe318b52b;
    bytes4 constant CHANGE_THRESHOLD = 0x694e80c3;
    bytes4 constant SET_FALLBACK = 0xf08a0323;

    function setUp() public {
        address[] memory whitelist = new address[](2);
        whitelist[0] = whitelisted1;
        whitelist[1] = whitelisted2;
        guard = new WhitelistGuard(safe, admin, whitelist);
    }

    // ========== CONSTRUCTOR TESTS ==========

    function test_constructor() public view {
        assertEq(guard.safe(), safe);
        assertEq(guard.admin(), admin);
        assertEq(guard.whitelistCount(), 2);
        assertTrue(guard.isWhitelisted(whitelisted1));
        assertTrue(guard.isWhitelisted(whitelisted2));
    }

    function test_constructor_revertsZeroSafe() public {
        address[] memory empty = new address[](0);
        vm.expectRevert(WhitelistGuard.ZeroAddress.selector);
        new WhitelistGuard(address(0), admin, empty);
    }

    function test_constructor_revertsZeroAdmin() public {
        address[] memory empty = new address[](0);
        vm.expectRevert(WhitelistGuard.ZeroAddress.selector);
        new WhitelistGuard(safe, address(0), empty);
    }

    // ========== WHITELIST TESTS ==========

    function test_addToWhitelist() public {
        vm.prank(admin);
        guard.addToWhitelist(address(0x3333));
        assertTrue(guard.isWhitelisted(address(0x3333)));
        assertEq(guard.whitelistCount(), 3);
    }

    function test_addToWhitelist_onlyAdmin() public {
        vm.prank(attacker);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.addToWhitelist(address(0x3333));
    }

    function test_removeFromWhitelist() public {
        vm.prank(admin);
        guard.removeFromWhitelist(whitelisted1);
        assertFalse(guard.isWhitelisted(whitelisted1));
        assertEq(guard.whitelistCount(), 1);
    }

    function test_addBatch() public {
        address[] memory batch = new address[](2);
        batch[0] = address(0x3333);
        batch[1] = address(0x4444);

        vm.prank(admin);
        guard.addBatch(batch);

        assertTrue(guard.isWhitelisted(address(0x3333)));
        assertTrue(guard.isWhitelisted(address(0x4444)));
        assertEq(guard.whitelistCount(), 4);
    }

    // ========== ADMIN FUNCTION BLOCKING TESTS ==========

    function test_blocks_setGuard() public {
        bytes memory data = abi.encodeWithSelector(SET_GUARD, address(0));
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, SET_GUARD));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_enableModule() public {
        bytes memory data = abi.encodeWithSelector(ENABLE_MODULE, attacker);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, ENABLE_MODULE));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_disableModule() public {
        bytes memory data = abi.encodeWithSelector(DISABLE_MODULE, address(0), admin);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, DISABLE_MODULE));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_addOwner() public {
        bytes memory data = abi.encodeWithSelector(ADD_OWNER, attacker, 1);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, ADD_OWNER));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_removeOwner() public {
        bytes memory data = abi.encodeWithSelector(REMOVE_OWNER, address(0), executor, 1);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, REMOVE_OWNER));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_swapOwner() public {
        bytes memory data = abi.encodeWithSelector(SWAP_OWNER, address(0), executor, attacker);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, SWAP_OWNER));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_changeThreshold() public {
        bytes memory data = abi.encodeWithSelector(CHANGE_THRESHOLD, 2);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, CHANGE_THRESHOLD));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_setFallback() public {
        bytes memory data = abi.encodeWithSelector(SET_FALLBACK, attacker);
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, SET_FALLBACK));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    // ========== DELEGATECALL TESTS ==========

    function test_blocks_delegatecall() public {
        vm.prank(safe);
        vm.expectRevert(WhitelistGuard.DelegateCallBlocked.selector);
        guard.checkTransaction(whitelisted1, 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_blocks_delegatecall_evenWithBypass() public {
        vm.prank(admin);
        guard.setBypass(true);

        vm.prank(safe);
        vm.expectRevert(WhitelistGuard.DelegateCallBlocked.selector);
        guard.checkTransaction(whitelisted1, 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(0), "", executor);
    }

    // ========== WHITELIST ENFORCEMENT TESTS ==========

    function test_allows_whitelisted() public {
        vm.prank(safe);
        guard.checkTransaction(whitelisted1, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
        // No revert = success
    }

    function test_blocks_nonWhitelisted() public {
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.NotWhitelisted.selector, notWhitelisted));
        guard.checkTransaction(notWhitelisted, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_allows_selfCall() public {
        vm.prank(safe);
        guard.checkTransaction(address(guard), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
        // No revert = success
    }

    // ========== BYPASS TESTS ==========

    function test_bypass_allowsAll() public {
        vm.prank(admin);
        guard.setBypass(true);

        vm.prank(safe);
        guard.checkTransaction(notWhitelisted, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
        // No revert = success
    }

    function test_bypass_stillBlocksAdminFunctions() public {
        vm.prank(admin);
        guard.setBypass(true);

        bytes memory data = abi.encodeWithSelector(SET_GUARD, address(0));
        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.AdminFunctionBlocked.selector, SET_GUARD));
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_bypass_onlyAdmin() public {
        vm.prank(attacker);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.setBypass(true);
    }

    // ========== ADMIN MANAGEMENT TESTS ==========

    function test_setAdmin() public {
        address newAdmin = address(0xAD222);
        vm.prank(admin);
        guard.setAdmin(newAdmin);
        assertEq(guard.admin(), newAdmin);
    }

    function test_setAdmin_onlyAdmin() public {
        vm.prank(attacker);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.setAdmin(attacker);
    }

    function test_lockAdmin() public {
        vm.prank(admin);
        guard.lockAdmin();
        assertTrue(guard.adminLocked());

        vm.prank(admin);
        vm.expectRevert(WhitelistGuard.AdminIsLocked.selector);
        guard.setAdmin(address(0x1234));
    }

    // ========== ATTACK SCENARIO TESTS ==========

    function test_attack_executorCannotRemoveGuard() public {
        bytes memory data = abi.encodeWithSelector(SET_GUARD, address(0));
        vm.prank(safe);
        vm.expectRevert();
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_attack_executorCannotAddModule() public {
        bytes memory data = abi.encodeWithSelector(ENABLE_MODULE, attacker);
        vm.prank(safe);
        vm.expectRevert();
        guard.checkTransaction(safe, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_attack_executorCannotBecomeAdmin() public {
        vm.prank(executor);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.setAdmin(executor);
    }

    function test_attack_executorCannotEnableBypass() public {
        vm.prank(executor);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.setBypass(true);
    }

    function test_attack_executorCannotWhitelistSelf() public {
        vm.prank(executor);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.addToWhitelist(attacker);
    }

    // ========== FUZZ TESTS ==========

    function testFuzz_blocksRandomAddress(address to) public {
        vm.assume(to != whitelisted1 && to != whitelisted2);
        vm.assume(to != address(guard) && to != safe);
        vm.assume(to != address(0));

        vm.prank(safe);
        vm.expectRevert(abi.encodeWithSelector(WhitelistGuard.NotWhitelisted.selector, to));
        guard.checkTransaction(to, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function testFuzz_adminCanWhitelistAny(address addr) public {
        vm.assume(addr != address(0));
        vm.assume(!guard.isWhitelisted(addr));

        vm.prank(admin);
        guard.addToWhitelist(addr);
        assertTrue(guard.isWhitelisted(addr));
    }

    // ========== SCENARIO TESTS ==========

    function test_scenario_dailyOperations() public {
        // Executor sends ETH to whitelisted address - should work
        vm.prank(safe);
        guard.checkTransaction(whitelisted1, 5 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);

        // Executor calls contract function on whitelisted - should work
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", address(0x1234), 1000);
        vm.prank(safe);
        guard.checkTransaction(whitelisted2, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_scenario_recovery() public {
        address recoveryDest = address(0xDEAD);

        // Can't send to non-whitelisted
        vm.prank(safe);
        vm.expectRevert();
        guard.checkTransaction(recoveryDest, 100 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);

        // Admin enables bypass
        vm.prank(admin);
        guard.setBypass(true);

        // Now can send anywhere
        vm.prank(safe);
        guard.checkTransaction(recoveryDest, 100 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);

        // Admin disables bypass
        vm.prank(admin);
        guard.setBypass(false);

        // Back to restricted
        vm.prank(safe);
        vm.expectRevert();
        guard.checkTransaction(recoveryDest, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(0), "", executor);
    }

    function test_scenario_adminTransfer() public {
        address newAdmin = address(0xAD222);

        vm.prank(admin);
        guard.setAdmin(newAdmin);

        // Old admin can't act
        vm.prank(admin);
        vm.expectRevert(WhitelistGuard.OnlyAdmin.selector);
        guard.addToWhitelist(address(0x3333));

        // New admin can
        vm.prank(newAdmin);
        guard.addToWhitelist(address(0x3333));
        assertTrue(guard.isWhitelisted(address(0x3333)));
    }
}

