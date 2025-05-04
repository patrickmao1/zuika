// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BLS12381} from "./BLS12381.sol";

contract LightClient {
// struct CheckpointData {
//     uint64 epochId;
//     uint64 sequenceNumber;
//     uint64 contentDigest;
//     uint64 previousDigest;
// }

// BLS12381 public bls;
// bytes32 public currentCommitteeRoot;

// event Verified(CheckpointData data);

// function updateCheckpoint(
//     bytes calldata checkpointIntent,
//     bytes memory sig,
//     bytes[] memory pubkeys,
//     uint256 signerMap
// ) public {
//     bytes32 committeeRoot = computeCommitteeRoot(pubkeys);
//     require(committeeRoot == currentCommitteeRoot, "Committee root mismatch");

//     bls.verifyAggSig(checkpointIntent, pubkeys, sig);
//     emit Verified(CheckpointData(0, 0, 0, 0));
// }

// function computeCommitteeRoot(bytes[] memory pubkeys) private pure returns (bytes32) {
//     return keccak256(abi.encodePacked(pubkeys));
// }
}
