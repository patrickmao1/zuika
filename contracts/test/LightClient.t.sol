// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import "../src/BLS12381.sol";
import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";
import {LightClient} from "../src/LightClient.sol";

contract LightClientTest is Test {
    LightClient public lightClient;
    Verifier public zkVerifier;
    BLS12381 public bls;

    function setUp() public {
        bls = new BLS12381();
        zkVerifier = new Verifier();
        lightClient = new LightClient(address(bls));
    }

    function test_updateCheckpoint1() public {
        bytes memory checkpointIntentBytes =
            hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        BLS12381.G1Point memory sig = BLS12381.G1Point(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2));
        BLS12381.G2Point[] memory pubkeys = new BLS12381.G2Point[](113);
        for (uint256 i = 0; i < 113; i++) {
            pubkeys[i] = BLS12381.G2Point(
                BLS12381.Fp2(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2)), BLS12381.Fp2(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2))
            );
        }
        lightClient.updateCheckpoint(checkpointIntentBytes, sig, pubkeys, 123);
    }

    function test_updateCheckpoint2() public {
        bytes memory checkpointIntentBytes =
            hex"020000e0020000000000007d870b08000000007c491ecb0000000020e767c5b2706f4d810d28664f9b5b0731d085156a3afcb72ddf67373cdf99057f012067d6d26500b1403a1a464cbd64d0aa61e02eace13f2c267f970f70bd3ed4fd38000000000000000000000000000000000000000000000000000000000000000038aed544960100000000020000e002000000000000";
        BLS12381.G1Point memory sig = BLS12381.G1Point(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2));
        lightClient.updateCheckpoint2(checkpointIntentBytes, sig, 123);
    }
}
