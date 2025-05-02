// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

contract BLSPrecompile {
    function test() public view returns (uint[4] memory output) {
        uint[2] memory input;
        input[0] = 20969780220420459542162176324821483620;
        input[1] = 51651680387027994973386178641854483779666245729743545944231128518233460393448;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                0x10,
                input,
                64,
                output,
                128
            )
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success, "call to map to curve precompile failed");

        return output;
    }
}