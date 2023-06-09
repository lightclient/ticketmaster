package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func newTicketMaster(t *testing.T) *TicketMaster {
	db, _ := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	rsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate rsa key: %v", err)
	}
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("unable to generate ecdsa key: %v", err)
	}
	return &TicketMaster{db: db, rsa: rsa, pk: pk}
}

func blindedTicket(ticket []byte, target rsa.PublicKey) (*big.Int, []byte) {
	// Generate blinding factor.
	buf := make([]byte, 32)
	if _, err := rand.Reader.Read(buf); err != nil {
		panic(err)
	}
	bFactor := new(big.Int).SetBytes(buf)
	bFactor = bFactor.Mod(bFactor, target.N)

	// Convert ticket to ticket digest.
	h := sha256.Sum256(ticket)
	d := new(big.Int).SetBytes(h[:])

	// Blind ticket.
	return bFactor, new(big.Int).Mod(d.Mul(d, new(big.Int).Exp(bFactor, big.NewInt(int64(target.E)), target.N)), target.N).Bytes()
}

func TestHandleTicket(t *testing.T) {
	var (
		tm               = newTicketMaster(t)
		srv              = httptest.NewServer(tm)
		ticket           = []byte("hello")
		bFactor, bTicket = blindedTicket(ticket, tm.rsa.PublicKey)
		txhash           = common.Hash{0x01}
	)
	defer tm.db.Close()
	defer srv.Close()

	// Set db with txhash => blinded ticket
	tm.db.Update(func(txn *badger.Txn) error {
		txn.Set(txhash[:], bTicket)
		txn.Commit()
		return nil
	})

	// Request ticket from master.
	var (
		url = fmt.Sprintf("%s/ticket", srv.URL)
		req = &ticketRequest{BlindedTicket: bTicket, TransactionHash: txhash}
		w   = bytes.NewBuffer(nil)
	)
	json.NewEncoder(w).Encode(req)
	resp, err := http.Post(url, "application/json", w)
	if err != nil {
		t.Fatalf("unexpected error from server: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed request, got status code %d", resp.StatusCode)
	}
	var res ticketResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("unable to decode server response: %v", err)
	}

	// Verify signature.
	sbTicket := new(big.Int).SetBytes(res.SignedBlindedTicket)
	sig := new(big.Int).Mod(sbTicket.Mul(sbTicket, bFactor.ModInverse(bFactor, tm.rsa.N)), tm.rsa.N)
	got := sig.Exp(sig, big.NewInt(int64(tm.rsa.PublicKey.E)), tm.rsa.N)
	want := sha256.Sum256(ticket)
	if !bytes.Equal(got.Bytes(), want[:]) {
		t.Fatalf("ticket master signature does not match expected: got %x, want %x", got.Bytes(), want[:])
	}
}
