// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {HashToField} from "../src/HashToField.sol";

contract HashToG1Test is Test {
    HashToField public h2g1;

    function test_hashToG1() public {
        bytes memory bs = new bytes(8);
        for (uint8 i = 0; i < bs.length; i++) {
            bs[i] = bytes1(i);
        }
        bytes memory output = h2g1.expandMessage(bs);
        console.logBytes(output);
    }
}
