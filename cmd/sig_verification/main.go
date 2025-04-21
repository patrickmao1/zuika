package main

import (
	"encoding/hex"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	key, err := hex.DecodeString("80477c651291fe6e6856b6190ecbe90fc1e41884bf8833fac13ada492cf28fb85dcdd55e080587cb1fa64e9c5b2465ec059eac3cc5bff931f04aa8bd960342748afe010a644d57c192acc0bc58f1414feb7bd197c2b53e253a830320c756308f")
	if err != nil {
		panic(err)
	}
	var point bls12381.G2Affine
	if err := point.Unmarshal(key); err != nil {
		panic(fmt.Sprintf("Failed to deserialize: %v", err))
	}

	fmt.Println(point)
}
