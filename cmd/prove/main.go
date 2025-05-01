package main

import (
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	dst := "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	g1, err := bls12381.HashToG1([]byte{1, 2, 3, 4}, []byte(dst))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", g1.X.String())
}
