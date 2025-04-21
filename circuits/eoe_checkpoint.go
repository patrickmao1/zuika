package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

type EndOfEpochCheckpointCircuit struct {
	api frontend.API

	PubKeys   []*sw_bls12381.G1Affine
	SignerMap []frontend.Variable // bits
	AggSig    sw_bls12381.G2Affine

	CheckpointPadded   []frontend.Variable
	CheckpointBytesLen frontend.Variable
	CheckpointDigest   [32]frontend.Variable `gnark:",public"`
	NumSigned          frontend.Variable     `gnark:",public"`
	CurrCommitteeRoot  frontend.Variable     `gnark:",public"`
	NextCommitteeRoot  frontend.Variable     `gnark:",public"`
}

func NewEndOfEpochCheckpointCircuit() *EndOfEpochCheckpointCircuit {
	return &EndOfEpochCheckpointCircuit{}
}

func (c *EndOfEpochCheckpointCircuit) Define(api frontend.API) error {
	//c.api = api
	//
	//rc := rangecheck.New(api)
	//for _, b := range c.SignerMap {
	//	rc.Check(b, 1)
	//}
	//
	//// check that checkpoint is signed by the current known committee
	//committeeRoot := computeCommitteeRoot(api, c.PubKeys)
	//api.AssertIsEqual(committeeRoot, c.CurrCommitteeRoot)
	//
	//// signature check
	//aggPubkey, numSigned := aggPubKeys(api, c.PubKeys, c.SignerMap)
	//api.AssertIsEqual(numSigned, c.NumSigned)
	//b2b := blake2b256.NewBlake2b(c.api)
	//digest := b2b.Blake2bBytes(c.CheckpointPadded, c.CheckpointBytesLen)
	//err := sw_bls12381.BlsAssertG2Verification(c.api, aggPubkey, c.AggSig, newU8Array(digest[:]))
	//if err != nil {
	//	return err
	//}
	//for i := range digest {
	//	api.AssertIsEqual(c.CheckpointDigest[i], digest[i])
	//}

	return nil
}
