// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BLS12381Helper} from "./BLS12381Helper.sol";

contract LightClient {
    struct CheckpointData {
        uint64 epochId;
        uint64 sequenceNumber;
        uint64 contentDigest;
        uint64 previousDigest;
    }

    BLS12381Helper public bls;

    event Verified(CheckpointData data);

    function updateCheckpoint(bytes calldata checkpointIntent) public {

        emit Verified(CheckpointData(0, 0, 0, 0));
    }
}
