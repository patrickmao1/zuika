// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

contract CommitteeSigVerifier {


    bytes[] public pubkeys;
    address public lightclient;

    modifier onlyLightClient() {
        require(msg.sender == lightclient, "Not the owner");
        _;
    }

    function setPubkeys(bytes[] memory _pubkeys) public onlyLightClient {
        pubkeys = _pubkeys;
    }

    function verifySig(bytes memory checkpointSummary, uint256 signerMap) public returns (bool) {

        return false;
    }
}