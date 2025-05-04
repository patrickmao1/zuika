// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import "./Verifier.sol";
import {BLS12381} from "./BLS12381.sol";
import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";

contract ZKLightClient {
    struct CheckpointData {
        uint64 epochId;
        uint64 sequenceNumber;
        uint64 contentDigest;
        uint64 previousDigest;
    }
    
    event Verified(CheckpointData data);

    BLS12381 public bls;
    address public zkVerifier;
    bytes4 public immutable verifyProofSelector;
    bytes32 public currentCommitteeRoot;

    constructor(address _zkVerifier, address _bls) {
        zkVerifier = _zkVerifier;
        bls = BLS12381(_bls);
        verifyProofSelector = bytes4(keccak256("verifyProof(uint256[8],uint256[2],uint256[2],uint256[7])"));
        currentCommitteeRoot = hex"1cf2542241bf7df9dd50fc28db1eb8104d7c293d6f53378d17d9688327c7afbb"; // for testing
    }

    function updateCheckpoint(bytes calldata checkpointIntent, bytes memory zkProof) public {
        bytes memory xmd = bls.expandMessage(checkpointIntent);
        uint256[3] memory fp0 = bytesToLimbs(Bytes.slice(xmd, 0, 64));
        uint256[3] memory fp1 = bytesToLimbs(Bytes.slice(xmd, 64, 128));

        bool pass = verifyProof(zkProof, abi.encodePacked(fp0, fp1, currentCommitteeRoot));
        require(pass, "invalid sig");

        CheckpointData memory data = extractCheckpointData(checkpointIntent);
        // emit Verified(data);
    }

    function bytesToLimbs(bytes memory b) internal pure returns (uint256[3] memory limbs) {
        limbs[0] = uint256(uint16(bytes2(Bytes.slice(b, 0, 2))));
        limbs[1] = uint256(uint248(bytes31(Bytes.slice(b, 2, 33))));
        limbs[2] = uint256(uint248(bytes31(Bytes.slice(b, 33, 64))));
        return limbs;
    }

    function extractCheckpointData(bytes calldata checkpoint) internal pure returns (CheckpointData memory data) {
        data = CheckpointData(
            uint64(bytes8(checkpoint[0:8])),
            uint64(bytes8(checkpoint[8:16])),
            uint64(bytes8(checkpoint[8:16])),
            uint64(bytes8(checkpoint[16:24]))
        );
    }

    function verifyProof(bytes memory proof, bytes memory input) public view returns (bool) {
        (bool success,) = zkVerifier.staticcall(abi.encodePacked(verifyProofSelector, proof, input));
        return success;
    }

    function setZkVerifier(address addr) external {
        zkVerifier = addr;
    }
}
