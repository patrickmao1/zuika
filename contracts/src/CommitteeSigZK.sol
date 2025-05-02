// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "./CommitteeSigVerifier.sol";
import {BLS12381Helper} from "./BLS12381Helper.sol";

contract CommitteeSigVerifier {

    struct CheckpointSummary {
        uint256 a;
    }

    address public zkVerifier;

    constructor(address _zkVerifier) {
        zkVerifier = _zkVerifier;
    }

    function setZkVerifier(address addr) external {
        zkVerifier = addr;
    }

    function verifySig(bytes memory proof, bytes memory input) external returns (bool) {
        (bool success,) = zkVerifier.staticcall(abi.encodePacked(hex"3f13bca6", proof, input));
        return success;
    }

    function decodeCheckpointSummary(bytes memory input) internal pure returns (CheckpointSummary memory) {
        return CheckpointSummary(1);
    }
}