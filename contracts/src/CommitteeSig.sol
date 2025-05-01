// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "./CommitteeSigVerifier.sol";
import {BLS12381Helper} from "./BLS12381Helper.sol";

contract CommitteeSigVerifier {

    Verifier public zkVerifier;

    constructor(address _zkVerifier) {
        zkVerifier = Verifier(_zkVerifier);
    }

    function setZkVerifier(address addr) external {
        zkVerifier = Verifier(addr);
    }

    function verifySig(bytes memory checkpointSummary, bytes32 committeeRoot) external pure returns (bool) {
        return false;
    }
}