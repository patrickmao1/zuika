package circuits

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"math/big"
	"testing"
)

func TestSimpleSig(t *testing.T) {
	privkeyBytes, err := hex.DecodeString("0e3acf35b5db46401eef7b7205b5c75d07721d9fc068b68bf5712552dbeb0532")
	require.NoError(t, err)
	privkey := new(big.Int).SetBytes(privkeyBytes)

	c := buildSimpleSigCircuit(t, privkey)
	a := buildSimpleSigCircuit(t, privkey)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(c, a, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BLS12_381))
}

func buildSimpleSigCircuit(t *testing.T, privkey *big.Int) *SimpleSigCircuit {
	msg := []byte("hello")
	h, err := blake2b.New(32, nil)
	require.NoError(t, err)
	h.Write(msg)
	digest := h.Sum(nil)
	var signingDigest []frontend.Variable
	for _, b := range digest {
		signingDigest = append(signingDigest, b)
	}

	_, _, _, g2Aff := bls12381.Generators()
	pubkey := g2Aff.ScalarMultiplicationBase(privkey)

	dstG1 := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
	xmd, err := bls12381.HashToG1(digest, dstG1)
	require.NoError(t, err)

	sig := new(bls12381.G1Affine)
	sig.ScalarMultiplication(&xmd, privkey)

	return &SimpleSigCircuit{
		PubKey:        sw_bls12381.NewG2Affine(*pubkey),
		AggSig:        sw_bls12381.NewG1Affine(*sig),
		SigningDigest: signingDigest,
	}
}

type SimpleSigCircuit struct {
	PubKey sw_bls12381.G2Affine
	AggSig sw_bls12381.G1Affine

	SigningDigest []frontend.Variable `gnark:",public"`
}

func (c *SimpleSigCircuit) Define(api frontend.API) error {
	verifySig(api, c.SigningDigest, &c.AggSig, &c.PubKey)
	return nil
}

func TestAggSig(t *testing.T) {
	c := buildAggSigCircuit(t)
	a := buildAggSigCircuit(t)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(c, a, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BLS12_381))
}

func buildAggSigCircuit(t *testing.T) *AggSigCircuit {
	msg := []byte("hello")
	h, err := blake2b.New(32, nil)
	require.NoError(t, err)
	h.Write(msg)
	digest := h.Sum(nil)
	var signingDigest []frontend.Variable
	for _, b := range digest {
		signingDigest = append(signingDigest, b)
	}

	dstG1 := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
	xmd, err := bls12381.HashToG1(digest, dstG1)
	require.NoError(t, err)

	signerMap := []frontend.Variable{1, 0, 1}
	privs, pubs := genBlsKeyPairs(3)
	sigs := signMulti(&xmd, privs, signerMap)
	agg := aggSigs(sigs)
	var pubkeys []sw_bls12381.G2Affine
	for _, pub := range pubs {
		pubkeys = append(pubkeys, sw_bls12381.NewG2Affine(*pub))
	}

	return &AggSigCircuit{
		PubKeys:       pubkeys,
		SignerMap:     signerMap,
		AggSig:        sw_bls12381.NewG1Affine(*agg),
		SigningDigest: signingDigest,
	}
}

type AggSigCircuit struct {
	PubKeys   []sw_bls12381.G2Affine
	SignerMap []frontend.Variable
	AggSig    sw_bls12381.G1Affine

	SigningDigest []frontend.Variable `gnark:",public"`
}

func (c *AggSigCircuit) Define(api frontend.API) error {
	aggPub := aggPubKeys(api, c.PubKeys, c.SignerMap)
	verifySig(api, c.SigningDigest, &c.AggSig, &aggPub)
	return nil
}

func aggSigs(sigs []bls12381.G1Affine) *bls12381.G1Affine {
	agg := new(bls12381.G1Affine)
	agg.SetInfinity()
	for _, sig := range sigs {
		agg.Add(agg, &sig)
	}
	return agg
}

func signMulti(xmd *bls12381.G1Affine, privs []*big.Int, signerMap []frontend.Variable) (sigs []bls12381.G1Affine) {
	for i, priv := range privs {
		if signerMap[i] == 0 {
			continue
		}
		sig := new(bls12381.G1Affine)
		sig.ScalarMultiplication(xmd, priv)
		sigs = append(sigs, *sig)
	}
	return sigs
}

func genBlsKeyPairs(n int) (privs []*big.Int, pubs []*bls12381.G2Affine) {
	for i := 0; i < n; i++ {
		p, q := genBlsKeyPair()
		privs = append(privs, p)
		pubs = append(pubs, q)
	}
	return
}

func genBlsKeyPair() (*big.Int, *bls12381.G2Affine) {
	privkey, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}
	pubkey := new(bls12381.G2Affine).ScalarMultiplicationBase(privkey)
	return privkey, pubkey
}
