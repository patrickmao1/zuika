// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BLS12381} from "./BLS12381.sol";

contract LightClient {
    struct CheckpointData {
        uint64 epochId;
        uint64 sequenceNumber;
        uint64 contentDigest;
        uint64 previousDigest;
    }

    BLS12381 public bls;
    bytes32 public currentCommitteeRoot;
    BLS12381.G2Point[] public pubkeys;

    constructor(address _bls) {
        bls = BLS12381(_bls);
        currentCommitteeRoot = hex"1cf2542241bf7df9dd50fc28db1eb8104d7c293d6f53378d17d9688327c7afbb"; // for testing
        pubkeys = new BLS12381.G2Point[](113);
        for (uint256 i = 0; i < 113; i++) {
            pubkeys[i] = BLS12381.G2Point(
                BLS12381.Fp2(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2)), BLS12381.Fp2(BLS12381.Fp(1, 2), BLS12381.Fp(1, 2))
            );
        }
    }

    event Verified(CheckpointData data);

    function updateCheckpoint(
        bytes calldata checkpointIntent,
        BLS12381.G1Point memory sig,
        BLS12381.G2Point[] memory _pubkeys,
        uint256 signerMap
    ) public {
        bytes32 committeeRoot = computeCommitteeRoot(_pubkeys);
        // require(committeeRoot == currentCommitteeRoot, "Committee root mismatch");

        BLS12381.G1Point memory msgOnCurve = bls.hashToG1(checkpointIntent);
        bool pass = bls.verifyAggSig(msgOnCurve, _pubkeys, sig);
        // require(pass, "invalid sig");
        emit Verified(CheckpointData(0, 0, 0, 0));
    }

    function computeCommitteeRoot(BLS12381.G2Point[] memory _pubkeys) private pure returns (bytes32) {
        bytes memory packed = new bytes(_pubkeys.length * 192);
        uint256 offset;

        for (uint256 i = 0; i < _pubkeys.length; ++i) {
            BLS12381.G2Point memory pk = _pubkeys[i];
            BLS12381.Fp[4] memory coords = [pk.X.a, pk.X.b, pk.Y.a, pk.Y.b];

            for (uint256 j = 0; j < 4; ++j) {
                uint256 fa = coords[j].a;
                uint256 fb = coords[j].b;

                assembly {
                    mstore(add(add(packed, 32), offset), shl(128, fa))
                    offset := add(offset, 16)
                    mstore(add(add(packed, 32), offset), fb)
                    offset := add(offset, 32)
                }
            }
        }

        return keccak256(packed);
    }

    function updateCheckpoint2(bytes calldata checkpointIntent, BLS12381.G1Point memory sig, uint256 signerMap)
        public
    {
        bytes32 committeeRoot = computeCommitteeRoot(pubkeys);
        // require(committeeRoot == currentCommitteeRoot, "Committee root mismatch");

        BLS12381.G1Point memory msgOnCurve = bls.hashToG1(checkpointIntent);
        bool pass = bls.verifyAggSig(msgOnCurve, pubkeys, sig);
        // require(pass, "invalid sig");
        emit Verified(CheckpointData(0, 0, 0, 0));
    }
}
