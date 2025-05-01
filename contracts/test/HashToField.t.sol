// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {HashToField} from "../src/HashToField.sol";

contract HashToG1Test is Test {
    HashToField public h2g1;

    function setUp() public {
        h2g1 = new HashToField();
    }

    function test_expandMessage() public {
        bytes memory checkpoint = hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        bytes memory output = h2g1.expandMessage(checkpoint);
        assertEq(hex"73ec811bf8564f6219db07ec09046e9da334dcefd0a3ee8124253173639d3bceb004f7932dd4cc0e13a4dd5e9af3756e95209f8a2a6fb98d50cb5a33fdb6e03a8003d3886768424cdddad753bcb0c88038a84d3c2bc799fe541edf37e77fa9788ee34fa27b85562bffd3e45761c20e8b4af8e2c9b94ac6fcd9f9e0a8217431df", output);
    }
}
