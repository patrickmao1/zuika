package tests

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/patrickmao1/zuika/circuits"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHello(t *testing.T) {
	c := circuits.MyCircuit{}
	a := circuits.MyCircuit{
		X: 3,
		Y: 3,
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	require.NoError(t, err)
	pk, vk, err := groth16.Setup(r1cs)
	witness, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
	require.NoError(t, err)
	proof, err := groth16.Prove(r1cs, pk, witness)
	require.NoError(t, err)
	pubWitness, err := witness.Public()
	require.NoError(t, err)
	err = groth16.Verify(proof, vk, pubWitness)
	require.NoError(t, err)
}
