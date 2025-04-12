package circuits

import "github.com/consensys/gnark/frontend"

type MyCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func (c *MyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)
	return nil
}
