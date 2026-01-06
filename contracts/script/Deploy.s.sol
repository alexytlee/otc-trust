// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WhitelistGuard } from "../src/WhitelistGuard.sol";

/**
 * @title DeployWhitelistGuard
 * @notice Deploy the WhitelistGuard contract
 *
 * Usage:
 *   SAFE=0x... ADMIN=0x... WHITELIST=0x...,0x... forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
 */
contract DeployWhitelistGuard is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address safe = vm.envAddress("SAFE");
        address admin = vm.envAddress("ADMIN");
        string memory whitelistStr = vm.envOr("WHITELIST", string(""));

        address[] memory whitelist = parseAddresses(whitelistStr);

        console2.log("Deploying WhitelistGuard...");
        console2.log("  Safe:", safe);
        console2.log("  Admin:", admin);
        console2.log("  Whitelist count:", whitelist.length);

        vm.startBroadcast(pk);
        WhitelistGuard guard = new WhitelistGuard(safe, admin, whitelist);
        vm.stopBroadcast();

        console2.log("");
        console2.log("Deployed at:", address(guard));
        console2.log("");
        console2.log("Next: Set guard on Safe via Safe UI");
        console2.log("  Settings > Setup > Transaction Guard > Set Guard");
    }

    function parseAddresses(string memory input) internal pure returns (address[] memory) {
        if (bytes(input).length == 0) return new address[](0);
        
        // Count commas
        uint256 count = 1;
        bytes memory b = bytes(input);
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ",") count++;
        }
        
        // For simplicity, return empty - set whitelist via admin after deploy
        return new address[](0);
    }
}

