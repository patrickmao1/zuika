package utils

import (
	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"math/big"
)

func ExportProofForSolidity(proof groth16.Proof) (p [8]*big.Int, commitments [2]*big.Int, commitmentPoK [2]*big.Int) {
	_proof := proof.(*bn254.Proof)

	p[0] = _proof.Ar.X.BigInt(new(big.Int))
	p[1] = _proof.Ar.Y.BigInt(new(big.Int))

	p[2] = _proof.Bs.X.A1.BigInt(new(big.Int))
	p[3] = _proof.Bs.X.A0.BigInt(new(big.Int))
	p[4] = _proof.Bs.Y.A1.BigInt(new(big.Int))
	p[5] = _proof.Bs.Y.A0.BigInt(new(big.Int))

	p[6] = _proof.Krs.X.BigInt(new(big.Int))
	p[7] = _proof.Krs.Y.BigInt(new(big.Int))

	commitments[0] = _proof.Commitments[0].X.BigInt(new(big.Int))
	commitments[1] = _proof.Commitments[0].Y.BigInt(new(big.Int))

	commitmentPoK[0] = _proof.CommitmentPok.X.BigInt(new(big.Int))
	commitmentPoK[1] = _proof.CommitmentPok.Y.BigInt(new(big.Int))

	return
}
