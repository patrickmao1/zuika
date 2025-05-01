// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {BLS12381Helper} from "./BLS12381Helper.sol";

contract CheckpointVerifier {
    BLS12381Helper.Fp public pubkeys;

    function setPubkeys(BLS12381Helper.Fp memory _pubkeys) external {
        pubkeys = _pubkeys;
    }

    function verifyCheckpoint() public view {

    }
}