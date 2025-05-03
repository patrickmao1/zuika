package circuits

import (
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
	"math/big"
	"slices"
)

type SigVerifyCircuit struct {
	api    frontend.API
	g1     *sw_bls12381.G1
	curveF *emulated.Field[emulated.BLS12381Fp]

	CommitteePubKeys    []sw_bls12381.G2Affine
	CommitteeStakeUnits []frontend.Variable
	SignerMap           []frontend.Variable // bits
	AggSig              sw_bls12381.G1Affine

	// expandMessageXmd output is 128 byte. split in middle and distributed each 64-byte slice to
	// 3 u248 limbs
	// 64 bytes
	CheckpointSummaryExpanded0 [3]frontend.Variable `gnark:",public"`
	CheckpointSummaryExpanded1 [3]frontend.Variable `gnark:",public"`
	CommitteeRoot              frontend.Variable    `gnark:",public"`
}

func (c *SigVerifyCircuit) Define(api frontend.API) error {
	c.api = api
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	c.g1 = g1
	field, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return err
	}
	c.curveF = field

	rc := rangecheck.New(api)
	for _, b := range c.SignerMap {
		rc.Check(b, 1)
	}

	signedStake := signedStakeUnits(api, c.CommitteeStakeUnits, c.SignerMap)
	api.AssertIsLessOrEqual(6667, signedStake)

	committeeRoot := commitPubKeys(api, c.CommitteePubKeys)
	api.AssertIsEqual(committeeRoot, c.CommitteeRoot)

	el0 := c.u248LimbsToElement(c.CheckpointSummaryExpanded0)
	el1 := c.u248LimbsToElement(c.CheckpointSummaryExpanded1)
	q0, err := c.g1.MapToG1(el0)
	if err != nil {
		return err
	}
	q1, err := c.g1.MapToG1(el1)
	if err != nil {
		return err
	}
	chkG1 := c.addG1(q0, q1)

	fmt.Printf("chkG1: %x %x\n", chkG1.X.Limbs, chkG1.Y.Limbs)
	aggPubkey := aggPubKeys(api, c.CommitteePubKeys, c.SignerMap)
	verifySig(api, chkG1, &c.AggSig, &aggPubkey)

	return nil
}

func (c *SigVerifyCircuit) fieldsToG1(a, b [3]frontend.Variable) (*sw_bls12381.G1Affine, error) {
	g1a, err := c.fieldToG1(a)
	if err != nil {
		return nil, err
	}
	g1b, err := c.fieldToG1(b)
	if err != nil {
		return nil, err
	}
	return c.addG1(g1a, g1b), nil
}

func (c *SigVerifyCircuit) fieldToG1(a [3]frontend.Variable) (*sw_bls12381.G1Affine, error) {
	api := c.api
	rc := rangecheck.New(api)

	// Recompose the already hash-to-fielded CheckpointSummary to 6 limbs
	limbs := make([]frontend.Variable, 0, 6)
	for _, limb128 := range a {
		rc.Check(limb128, 128)

		limb128Bits := api.ToBinary(limb128, 128)
		hi := api.FromBinary(limb128Bits[:64]...)
		lo := api.FromBinary(limb128Bits[64:]...)

		limbs = append(limbs, hi, lo)
	}
	// Reverse endianness as gnark works with little-endian limbs
	slices.Reverse(limbs)
	el := &emulated.Element[emulated.BLS12381Fp]{Limbs: limbs}
	return c.g1.MapToG1(el)
}

// Taken from a non-exported function in gnark
func (c *SigVerifyCircuit) addG1(p, q *sw_bls12381.G1Affine) *sw_bls12381.G1Affine {
	mone := c.curveF.NewElement(-1)
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := c.curveF.Sub(&q.Y, &p.Y)
	qxpx := c.curveF.Sub(&q.X, &p.X)
	λ := c.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := c.curveF.Eval([][]*emulated.Element[emulated.BLS12381Fp]{{λ, λ}, {mone, c.curveF.Add(&p.X, &q.X)}}, []int{1, 1})

	// p.y = λ(p.x-xr) - p.y
	yr := c.curveF.Eval([][]*emulated.Element[emulated.BLS12381Fp]{{λ, c.curveF.Sub(&p.X, xr)}, {mone, &p.Y}}, []int{1, 1})

	return &sw_bls12381.G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func aggPubKeys(api frontend.API, pubkeys []sw_bls12381.G2Affine, signerMap []frontend.Variable) sw_bls12381.G2Affine {
	if len(pubkeys) != len(signerMap) {
		panic("len(pubkeys) != len(signerMap)")
	}

	z := new(bls12381.G2Affine).SetInfinity()
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

func verifySig(api frontend.API, msgG1 *sw_bls12381.G1Affine, sig *sw_bls12381.G1Affine, pubkey *sw_bls12381.G2Affine) {
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
	pairing.AssertIsOnG1(msgG1)

	rhs, err := pairing.Pair([]*sw_bls12381.G1Affine{msgG1}, []*sw_bls12381.G2Affine{pubkey})
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

func (c *SigVerifyCircuit) u248LimbsToElement(limbs [3]frontend.Variable) *emulated.Element[emulated.BLS12381Fp] {
	api := c.api
	fp := c.curveF

	// input is big-endian, we need little-endian
	slices.Reverse(limbs[:])

	// Input is 512 bits in three 248-bit limbs
	// The first limb contains only 2 bytes

	bits := make([]frontend.Variable, 0, 512)
	l0 := api.ToBinary(limbs[0], 256)
	for _, b := range l0[248:] {
		api.AssertIsEqual(b, 0) // range check 248 bits
	}
	bits = append(bits, l0[:248]...)

	l1 := api.ToBinary(limbs[1], 256)
	for _, b := range l1[248:] {
		api.AssertIsEqual(b, 0) // range check 248 bits
	}
	bits = append(bits, l1[:248]...)

	l2 := api.ToBinary(limbs[2], 256)
	for _, b := range l2[16:] {
		api.AssertIsEqual(b, 0) // range check 16 bits
	}
	bits = append(bits, l2[:16]...)

	cutoff := 17
	tailBits, headBits := bits[:cutoff*8], bits[cutoff*8:]
	tail := fp.FromBits(tailBits...)
	head := fp.FromBits(headBits...)

	byteMultiplier := big.NewInt(256)
	headMultiplier := byteMultiplier.Exp(byteMultiplier, big.NewInt(int64(cutoff)), big.NewInt(0))
	head = fp.MulConst(head, headMultiplier)

	return fp.Add(head, tail)
}
