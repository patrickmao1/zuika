// SPDX-License-Identifier: UNLICENSED

// Code taken from https://github.com/ralexstokes/deposit-verifier/blob/8da90a8f6fc686ab97506fd0d84568308b72f133/deposit_verifier.sol
// with some modifications to adapt to the G1 version of hash-to-field

pragma solidity ^0.8.29;

contract HashToField {
    uint8 private constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;
    uint8 private constant BLS12_381_MAP_G1_PRECOMPILE_ADDRESS = 0x10;
    // Note: the last char "+" results from RFC9380: DST_prime = DST || I2OSP(len(DST), 1), which is 0x43, which is "+" in ascii
    string private constant BLS_SIG_DST_PRIME = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+";

    struct Fp {
        uint a;
        uint b;
    }

    function expandMessage(bytes memory message) public pure returns (bytes memory) {
        uint len = message.length;
        bytes memory b0Input = new bytes(111 + len);
        // Z_pad = I2OSP(0, s_in_bytes)
        // msg_prime = Z_pad || msg || ...
        for (uint i = 0; i < len; i++) {
            b0Input[i + 64] = message[i];
        }

        uint offset = 64 + len;

        // l_i_b_str = I2OSP(len_in_bytes, 2)
        b0Input[offset] = 0x00;
        b0Input[offset + 1] = 0x80; // for hash to G1 we need a 128-byte output
        // I2OSP(0, 1)
        b0Input[offset + 2] = 0x00;

        offset = offset + 3;

        // DST_prime = DST || I2OSP(len(DST), 1)
        for (uint i = 0; i < 44; i++) {
            b0Input[offset + i] = bytes(BLS_SIG_DST_PRIME)[i];
        }

        // b_0 = H(msg_prime)
        bytes32 b0 = sha256(abi.encodePacked(b0Input));

        bytes memory output = new bytes(128);

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        bytes32 b1 = sha256(abi.encodePacked(b0, bytes1(0x01), bytes(BLS_SIG_DST_PRIME)));
        assembly {
            mstore(add(output, 0x20), b1)
        }
        // ell = ceil(len_in_bytes / b_in_bytes) = ceil(128 / 32) where 128 is the output len and 32 is the sha256 hash len
        // for i in (2, ..., ell):
        for (uint i = 2; i < 5; i++) {
            // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
            bytes32 input;
            assembly {
                input := xor(b0, mload(add(output, add(0x20, mul(0x20, sub(i, 2))))))
            }
            bytes32 bi = sha256(abi.encodePacked(input, uint8(i), bytes(BLS_SIG_DST_PRIME)));
            assembly {
                mstore(add(output, add(0x20, mul(0x20, sub(i, 1)))), bi)
            }
        }

        return output;
    }

    function sliceToUint(bytes memory data, uint start, uint end) private pure returns (uint) {
        uint length = end - start;
        assert(length >= 0);
        assert(length <= 32);

        uint result;
        for (uint i = 0; i < length; i++) {
            bytes1 b = data[start + i];
            result = result + (uint8(b) * 2 ** (8 * (length - i - 1)));
        }
        return result;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    // Copying of the base is cribbed from the following:
    // https://github.com/ethereum/solidity-examples/blob/f44fe3b3b4cca94afe9c2a2d5b7840ff0fafb72e/src/unsafe/Memory.sol#L57-L74
    function reduceModulo(bytes memory data, uint start, uint end) private view returns (bytes memory) {
        uint length = end - start;
        assert(length >= 0);
        assert(length <= data.length);

        bytes memory result = new bytes(48);

        bool success;
        assembly {
            let p := mload(0x40)
        // length of base
            mstore(p, length)
        // length of exponent
            mstore(add(p, 0x20), 0x20)
        // length of modulus
            mstore(add(p, 0x40), 48)
        // base
        // first, copy slice by chunks of EVM words
            let ctr := length
            let src := add(add(data, 0x20), start)
            let dst := add(p, 0x60)
            for {}
            or(gt(ctr, 0x20), eq(ctr, 0x20))
            {ctr := sub(ctr, 0x20)}
            {
                mstore(dst, mload(src))
                dst := add(dst, 0x20)
                src := add(src, 0x20)
            }
        // next, copy remaining bytes in last partial word
            let mask := sub(exp(256, sub(0x20, ctr)), 1)
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dst), mask)
            mstore(dst, or(destpart, srcpart))
        // exponent
            mstore(add(p, add(0x60, length)), 1)
        // modulus
            let modulusAddr := add(p, add(0x60, add(0x10, length)))
            mstore(modulusAddr, or(mload(modulusAddr), 0x1a0111ea397fe69a4b1ba7b6434bacd7)) // pt 1
            mstore(add(p, add(0x90, length)), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab) // pt 2
            success := staticcall(
                sub(gas(), 2000),
                MOD_EXP_PRECOMPILE_ADDRESS,
                p,
                add(0xB0, length),
                add(result, 0x20),
                48)
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success, "call to modular exponentiation precompile failed");
        return result;
    }

    function convertSliceToFp(bytes memory data, uint start, uint end) private view returns (Fp memory) {
        bytes memory fieldElement = reduceModulo(data, start, end);
        uint a = sliceToUint(fieldElement, 0, 16);
        uint b = sliceToUint(fieldElement, 16, 48);
        return Fp(a, b);
    }

    function hashToField(bytes memory message) public view returns (Fp[2] memory result) {
        bytes memory some_bytes = expandMessage(message);
        result[0] = convertSliceToFp(some_bytes, 0, 64);
        result[1] = convertSliceToFp(some_bytes, 64, 128);
        return result;
    }
}