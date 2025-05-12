// SPDX-License-Identifier: UNLICENSED

// Code taken from https://github.com/ralexstokes/deposit-verifier/blob/8da90a8f6fc686ab97506fd0d84568308b72f133/deposit_verifier.sol
// with modifications to adapt to the "short signature" form of bls

pragma solidity ^0.8.29;

contract BLS12381 {
    uint8 private constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;
    uint8 private constant BLS12_381_G1_ADD_ADDRESS = 0x0b;
    uint8 private constant BLS12_381_G2_ADD_ADDRESS = 0x0d;
    uint8 private constant BLS12_381_MAP_G1_PRECOMPILE_ADDRESS = 0x10;
    uint8 private constant BLS12_381_PAIRING_PRECOMPILE_ADDRESS = 0x0f;

    bytes1 private constant BLS_BYTE_WITHOUT_FLAGS_MASK = bytes1(0x1f);

    // NOTE: the last char "+" results from RFC9380: DST_prime = DST || I2OSP(len(DST), 1), which is 0x43, which is "+" in ascii
    string private constant BLS_SIG_DST_PRIME = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_+";

    struct Fp {
        uint256 a;
        uint256 b;
    }

    struct Fp2 {
        Fp a;
        Fp b;
    }

    struct G1Point {
        Fp X;
        Fp Y;
    }

    struct G2Point {
        Fp2 X;
        Fp2 Y;
    }

    function verifyAggSig(G1Point memory msgOnCurve, G2Point[] memory pubkeys, G1Point memory sig)
        public
        view
        returns (bool)
    {
        G2Point memory aggPubkey = pubkeys[0];
        for (uint256 i = 1; i < pubkeys.length; i++) {
            aggPubkey = addG2(aggPubkey, pubkeys[i]);
        }
        return pairingCheck(aggPubkey, msgOnCurve, sig);
    }

    function expandMessage(bytes memory message) public pure returns (bytes memory) {
        uint256 len = message.length;
        bytes memory b0Input = new bytes(111 + len);
        // Z_pad = I2OSP(0, s_in_bytes)
        // msg_prime = Z_pad || msg || ...
        for (uint256 i = 0; i < len; i++) {
            b0Input[i + 64] = message[i];
        }

        uint256 offset = 64 + len;

        // l_i_b_str = I2OSP(len_in_bytes, 2)
        b0Input[offset] = 0x00;
        b0Input[offset + 1] = 0x80; // for hash to G1 we need a 128-byte output
        // I2OSP(0, 1)
        b0Input[offset + 2] = 0x00;

        offset = offset + 3;

        // DST_prime = DST || I2OSP(len(DST), 1)
        for (uint256 i = 0; i < 44; i++) {
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
        for (uint256 i = 2; i < 5; i++) {
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

    function pairingCheck(G2Point memory publicKey, G1Point memory messageOnCurve, G1Point memory signature)
        public
        view
        returns (bool)
    {
        uint256[24] memory input;

        input[0] = publicKey.X.a.a;
        input[1] = publicKey.X.a.b;
        input[2] = publicKey.X.b.a;
        input[3] = publicKey.X.b.b;
        input[4] = publicKey.Y.a.a;
        input[5] = publicKey.Y.a.b;
        input[6] = publicKey.Y.b.a;
        input[7] = publicKey.Y.b.b;

        input[8] = messageOnCurve.X.a;
        input[9] = messageOnCurve.X.b;
        input[10] = messageOnCurve.Y.a;
        input[11] = messageOnCurve.Y.b;

        // NOTE: this constant is -P2, where P2 is the generator of the group G1.
        input[12] = 0x13e02b6052719f607dacd3a088274f65;
        input[13] = 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
        input[14] = 0x024aa2b2f08f0a91260805272dc51051;
        input[15] = 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
        input[16] = 0x13fa4d4a0ad8b1ce186ed5061789213d;
        input[17] = 0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed;
        input[18] = 0x0d1b3cc2c7027888be51d9ef691d77bc;
        input[19] = 0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa;

        input[20] = signature.X.a;
        input[21] = signature.X.b;
        input[22] = signature.Y.a;
        input[23] = signature.Y.b;

        uint256[1] memory output;

        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), BLS12_381_PAIRING_PRECOMPILE_ADDRESS, input, 768, output, 32)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "call to pairing precompile failed");

        return output[0] == 1;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    // Copying of the base is cribbed from the following:
    // https://github.com/ethereum/solidity-examples/blob/f44fe3b3b4cca94afe9c2a2d5b7840ff0fafb72e/src/unsafe/Memory.sol#L57-L74
    function reduceModulo(bytes memory data, uint256 start, uint256 end) public view returns (bytes memory) {
        uint256 length = end - start;
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
            for {} or(gt(ctr, 0x20), eq(ctr, 0x20)) { ctr := sub(ctr, 0x20) } {
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
            success :=
                staticcall(sub(gas(), 2000), MOD_EXP_PRECOMPILE_ADDRESS, p, add(0xB0, length), add(result, 0x20), 48)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "call to modular exponentiation precompile failed");
        return result;
    }

    function decodeG1Point(bytes memory encodedX, Fp memory Y) private pure returns (G1Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        uint256 a = sliceToUint(encodedX, 0, 16);
        uint256 b = sliceToUint(encodedX, 16, 48);
        Fp memory X = Fp(a, b);
        return G1Point(X, Y);
    }

    function decodeG2Point(bytes memory encodedX, Fp2 memory Y) private pure returns (G2Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        // NOTE: the "flag bits" of the second half of `encodedX` are always == 0x0

        // NOTE: order is important here for decoding point...
        uint256 aa = sliceToUint(encodedX, 48, 64);
        uint256 ab = sliceToUint(encodedX, 64, 96);
        uint256 ba = sliceToUint(encodedX, 0, 16);
        uint256 bb = sliceToUint(encodedX, 16, 48);
        Fp2 memory X = Fp2(Fp(aa, ab), Fp(ba, bb));
        return G2Point(X, Y);
    }

    function mapG1(Fp memory el) public view returns (G1Point memory result) {
        uint256[2] memory input;
        input[0] = el.a;
        input[1] = el.b;

        uint256[4] memory output;

        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), BLS12_381_MAP_G1_PRECOMPILE_ADDRESS, input, 64, output, 128)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "call to map to curve precompile failed");

        return G1Point(Fp(output[0], output[1]), Fp(output[2], output[3]));
    }

    function addG1(G1Point memory a, G1Point memory b) public view returns (G1Point memory) {
        uint256[8] memory input;
        input[0] = a.X.a;
        input[1] = a.X.b;
        input[2] = a.Y.a;
        input[3] = a.Y.b;

        input[4] = b.X.a;
        input[5] = b.X.b;
        input[6] = b.Y.a;
        input[7] = b.Y.b;

        uint256[4] memory output;

        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), BLS12_381_G1_ADD_ADDRESS, input, 256, output, 128)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "call to addition in G2 precompile failed");

        return G1Point(Fp(output[0], output[1]), Fp(output[2], output[3]));
    }

    function addG2(G2Point memory a, G2Point memory b) private view returns (G2Point memory) {
        uint256[16] memory input;
        input[0] = a.X.a.a;
        input[1] = a.X.a.b;
        input[2] = a.X.b.a;
        input[3] = a.X.b.b;
        input[4] = a.Y.a.a;
        input[5] = a.Y.a.b;
        input[6] = a.Y.b.a;
        input[7] = a.Y.b.b;

        input[8] = b.X.a.a;
        input[9] = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;
        input[12] = b.Y.a.a;
        input[13] = b.Y.a.b;
        input[14] = b.Y.b.a;
        input[15] = b.Y.b.b;

        uint256[8] memory output;

        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), BLS12_381_G2_ADD_ADDRESS, input, 512, output, 256)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "call to addition in G2 precompile failed");

        return G2Point(
            Fp2(Fp(output[0], output[1]), Fp(output[2], output[3])),
            Fp2(Fp(output[4], output[5]), Fp(output[6], output[7]))
        );
    }

    function hashToG1Bytes(bytes memory message) public view returns (bytes memory g1Bytes) {
        G1Point memory g1 = hashToG1(message);
        return encodeG1PointPacked(g1);
    }

    function hashToG1(bytes memory message) public view returns (G1Point memory g1) {
        Fp[2] memory els = hashToField(message);
        G1Point memory point1 = mapG1(els[0]);
        G1Point memory point2 = mapG1(els[1]);
        return addG1(point1, point2);
    }

    function hashToField(bytes memory message) public view returns (Fp[2] memory result) {
        bytes memory some_bytes = expandMessage(message);
        result[0] = convertSliceToFp(some_bytes, 0, 64);
        result[1] = convertSliceToFp(some_bytes, 64, 128);
        return result;
    }

    function encodeG1PointPacked(G1Point memory g1) public pure returns (bytes memory g1Bytes) {
        return bytes.concat(bytes32(g1.X.a), bytes32(g1.X.b), bytes32(g1.Y.a), bytes32(g1.Y.b));
    }

    function convertSliceToFp(bytes memory data, uint256 start, uint256 end) private view returns (Fp memory) {
        bytes memory fieldElement = reduceModulo(data, start, end);
        uint256 a = sliceToUint(fieldElement, 0, 16);
        uint256 b = sliceToUint(fieldElement, 16, 48);
        return Fp(a, b);
    }

    function sliceToUint(bytes memory data, uint256 start, uint256 end) private pure returns (uint256) {
        uint256 length = end - start;
        assert(length >= 0);
        assert(length <= 32);

        uint256 result;
        for (uint256 i = 0; i < length; i++) {
            bytes1 b = data[start + i];
            result = result + (uint8(b) * 2 ** (8 * (length - i - 1)));
        }
        return result;
    }
}
