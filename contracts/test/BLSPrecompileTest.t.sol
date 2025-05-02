// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import "../src/BLS12381Helper.sol";
import {BLS12381Helper} from "../src/BLS12381Helper.sol";
import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "../src/CommitteeSigVerifier.sol";
import {BLSPrecompile} from "../src/BLSPrecompile.sol";

contract BLSPrecompileTest is Test {
    BLSPrecompile public bls;

    function setUp() public {
        bls = new BLSPrecompile();
    }

    function test_test() public {
        uint[4] memory output = bls.test();
        for (uint i = 0; i < 4; i++) {
            console.logUint(output[i]);
        }
    }
}
