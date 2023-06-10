package main

import (
	"bytes"
	"crypto/rsa"
	"math/big"
)

// signBlindedTicket signs the ticket with the coordinator's rsa private key.
func signBlindedTicket(sk *rsa.PrivateKey, ticket []byte) []byte {
	t := new(big.Int).SetBytes(ticket)
	return t.Exp(t, sk.D, sk.N).Bytes()
}

// verifySignature verifies that sig was created by the rsa key over the
// provided msg.
func verifySignature(pk *rsa.PublicKey, sig []byte, msg []byte) bool {
	s := big.NewInt(0).SetBytes(sig)
	got := s.Exp(s, big.NewInt(int64(pk.E)), pk.N).Bytes()
	return bytes.Compare(got, msg) == 0
}
