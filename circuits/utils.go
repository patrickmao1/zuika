package circuits

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/uints"
)

func newU8Array(data []frontend.Variable) []uints.U8 {
	ret := make([]uints.U8, len(data))
	for i, b := range data {
		ret[i].Val = b
	}
	return ret
}

func aggPubKeys(api frontend.API, pubkeys []sw_bls12381.G2Affine, signerMap []frontend.Variable) sw_bls12381.G2Affine {
	if len(pubkeys) != len(signerMap) {
		panic("len(pubkeys) != len(signerMap)")
	}

	z := new(bls12381.G2Affine)
	z.SetInfinity()
	zero := sw_bls12381.NewG2Affine(*z)
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		panic(err)
	}

	agg := &zero
	for i, bit := range signerMap {
		agg = g2.Select(bit, g2.AddUnified(agg, &pubkeys[i]), agg)
	}

	return *agg
}

func signedStakeUnits(api frontend.API, stakes, signerMap []frontend.Variable) frontend.Variable {
	if len(stakes) != len(signerMap) {
		panic("len(pubkeys) != len(stakes)")
	}
	signedStake := frontend.Variable(0)
	for i, bit := range signerMap {
		signedStake = api.Select(bit, api.Add(signedStake, stakes[i]), signedStake)
	}
	return signedStake
}

func verifySig(api frontend.API, msg []frontend.Variable, sig *sw_bls12381.G1Affine, pubkey *sw_bls12381.G2Affine) {
	_, _, _, g2GenNative := bls12381.Generators()
	g2Gen := sw_bls12381.NewG2Affine(g2GenNative)
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		panic(err)
	}
	pairing.AssertIsOnG1(sig)
	pairing.AssertIsOnG2(pubkey)

	lhs, err := pairing.Pair([]*sw_bls12381.G1Affine{sig}, []*sw_bls12381.G2Affine{&g2Gen})
	if err != nil {
		panic(err)
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		panic(err)
	}
	dstG1 := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
	hm, err := g1.HashToG1(newU8Array(msg), dstG1)
	if err != nil {
		panic(err)
	}
	pairing.AssertIsOnG1(hm)

	rhs, err := pairing.Pair([]*sw_bls12381.G1Affine{hm}, []*sw_bls12381.G2Affine{pubkey})
	if err != nil {
		panic(err)
	}
	pairing.AssertIsEqual(lhs, rhs)
}

func commitPubKeys(api frontend.API, pubkeys []sw_bls12381.G2Affine) frontend.Variable {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	for _, pubkey := range pubkeys {
		h.Write(pubkey.P.X.A0.Limbs...)
		h.Write(pubkey.P.X.A1.Limbs...)
	}
	return h.Sum()
}
