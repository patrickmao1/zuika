package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/rangecheck"
)

type SigVerifyCircuit struct {
	api frontend.API `gnark:"-"`

	CommitteePubKeys    []sw_bls12381.G2Affine
	CommitteeStakeUnits []frontend.Variable
	SignerMap           []frontend.Variable // bits
	AggSig              sw_bls12381.G1Affine

	CheckpointSummaryG1 sw_bls12381.G1Affine `gnark:",public"`
	CommitteeRoot       frontend.Variable    `gnark:",public"`
}

func (c *SigVerifyCircuit) Define(api frontend.API) error {
	c.api = api

	rc := rangecheck.New(api)
	for _, b := range c.SignerMap {
		rc.Check(b, 1)
	}

	signedStake := signedStakeUnits(api, c.CommitteeStakeUnits, c.SignerMap)
	api.AssertIsLessOrEqual(6667, signedStake)

	committeeRoot := commitPubKeys(api, c.CommitteePubKeys)
	api.AssertIsEqual(committeeRoot, c.CommitteeRoot)

	aggPubkey := aggPubKeys(api, c.CommitteePubKeys, c.SignerMap)
	verifySig(api, &c.CheckpointSummaryG1, &c.AggSig, &aggPubkey)

	return nil
}
