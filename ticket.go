package main

import (
	"crypto/rsa"
	"math/big"
)

func signTicket(pk *rsa.PrivateKey, ticket []byte) []byte {
	t := new(big.Int).SetBytes(ticket)
	t.Exp(t, pk.D, pk.N)
	return t.Bytes()
}
