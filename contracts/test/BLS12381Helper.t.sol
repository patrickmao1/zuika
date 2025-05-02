// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import "../src/BLS12381Helper.sol";
import {BLS12381Helper} from "../src/BLS12381Helper.sol";
import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "../src/CommitteeSigVerifier.sol";

contract BLS12381HelperTest is Test {
    BLS12381Helper public bls;

    function setUp() public {
        bls = new BLS12381Helper();
    }

    function test_expandMessage() public {
        bytes memory checkpoint = hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        bytes memory output = bls.expandMessage(checkpoint);
        assertEq(hex"73ec811bf8564f6219db07ec09046e9da334dcefd0a3ee8124253173639d3bceb004f7932dd4cc0e13a4dd5e9af3756e95209f8a2a6fb98d50cb5a33fdb6e03a8003d3886768424cdddad753bcb0c88038a84d3c2bc799fe541edf37e77fa9788ee34fa27b85562bffd3e45761c20e8b4af8e2c9b94ac6fcd9f9e0a8217431df", output);
    }

    function test_hashToField() public {
        bytes memory checkpoint = hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        BLS12381Helper.Fp[2] memory output = bls.hashToField(checkpoint);
        bytes memory fp0 = abi.encodePacked(output[0].a, output[0].b);
        bytes memory fp1 = abi.encodePacked(output[1].a, output[1].b);
        assertEq(hex"000000000000000000000000000000000fc6a1fce955c2694d22e2ad2a8e80647231d0a9d95b66283a5e382d27f3fc06ba52ccb8bced669825f046d356cd45e8", fp0);
        assertEq(hex"000000000000000000000000000000000c7db6a4667623b85871b73da7c46615b2b980f5a23ef492c85c28dc29ebf4838845fa70ab6e936933e53f86eac17adc", fp1);
    }

    function test_hashToG1() public {
        bytes memory checkpoint = hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        BLS12381Helper.G1Point memory g1 = bls.hashToG1(checkpoint);
        console.log("g1 X a", g1.X.a);
        console.log("g1 X b", g1.X.b);
        console.log("g1 Y a", g1.Y.a);
        console.log("g1 Y b", g1.Y.b);
    }
}
