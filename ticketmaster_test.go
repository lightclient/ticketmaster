package main

import (
	"bytes"
	"context"
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
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
)

var (
	testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr    = crypto.PubkeyToAddress(testKey.PublicKey)
	testBalance = big.NewInt(2e18)
)

var genesis = &core.Genesis{
	Config:    params.SepoliaChainConfig,
	Alloc:     core.GenesisAlloc{testAddr: {Balance: testBalance}},
	ExtraData: []byte("test genesis"),
	Timestamp: 9000,
	BaseFee:   big.NewInt(params.InitialBaseFee),
}

var testTx1 = types.MustSignNewTx(testKey, types.LatestSigner(genesis.Config), &types.LegacyTx{
	Nonce:    0,
	Value:    big.NewInt(12),
	GasPrice: big.NewInt(params.InitialBaseFee),
	Gas:      params.TxGas,
	To:       &common.Address{2},
})

var testTx2 = types.MustSignNewTx(testKey, types.LatestSigner(genesis.Config), &types.LegacyTx{
	Nonce:    1,
	Value:    big.NewInt(8),
	GasPrice: big.NewInt(params.InitialBaseFee),
	Gas:      params.TxGas,
	To:       &common.Address{2},
})

func newTestBackend(t *testing.T) (*node.Node, []*types.Block) {
	// Generate test chain.
	blocks := generateTestChain()

	// Create node
	n, err := node.New(&node.Config{})
	if err != nil {
		t.Fatalf("can't create new node: %v", err)
	}
	// Create Ethereum Service
	config := &ethconfig.Config{Genesis: genesis}
	ethservice, err := eth.New(n, config)
	if err != nil {
		t.Fatalf("can't create new ethereum service: %v", err)
	}
	// Import the test chain.
	if err := n.Start(); err != nil {
		t.Fatalf("can't start test node: %v", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks[1:]); err != nil {
		t.Fatalf("can't import test blocks: %v", err)
	}
	return n, blocks
}

func generateTestChain() []*types.Block {
	generate := func(i int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		if i == 1 {
			// Test transactions are included in block #2.
			g.AddTx(testTx1)
			g.AddTx(testTx2)
		}
	}
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), 2, generate)
	return append([]*types.Block{genesis.ToBlock()}, blocks...)
}

func newTicketMaster(t *testing.T, client *ethclient.Client) *TicketMaster {
	db, _ := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	rsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate rsa key: %v", err)
	}
	return &TicketMaster{db: db, rsa: rsa, pk: testKey, client: client}
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

func signTicket(ticket []byte, target *rsa.PrivateKey) []byte {
	bFactor, bTicket := blindedTicket(ticket, target.PublicKey)
	sbTicket := new(big.Int).SetBytes(bTicket)
	sbTicket = sbTicket.Exp(sbTicket, target.D, target.N)
	return new(big.Int).Mod(sbTicket.Mul(sbTicket, bFactor.ModInverse(bFactor, target.N)), target.N).Bytes()
}

func TestHandleTicket(t *testing.T) {
	var (
		tm               = newTicketMaster(t, nil)
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
	sbTicket := new(big.Int).SetBytes(res.SignedBlindedTicket[0])
	sig := new(big.Int).Mod(sbTicket.Mul(sbTicket, bFactor.ModInverse(bFactor, tm.rsa.N)), tm.rsa.N)
	got := sig.Exp(sig, big.NewInt(int64(tm.rsa.PublicKey.E)), tm.rsa.N)
	want := sha256.Sum256(ticket)
	if !bytes.Equal(got.Bytes(), want[:]) {
		t.Fatalf("ticket master signature does not match expected: got %x, want %x", got.Bytes(), want[:])
	}
}

func TestFundAccount(t *testing.T) {
	var (
		ticket     = []byte("hello")
		backend, _ = newTestBackend(t)
		rpc, _     = backend.Attach()
		client     = ethclient.NewClient(rpc)
		tm         = newTicketMaster(t, client)
		srv        = httptest.NewServer(tm)
	)
	defer backend.Close()
	defer client.Close()
	defer tm.db.Close()
	defer srv.Close()

	// Request funds.
	var (
		url = fmt.Sprintf("%s/fund", srv.URL)
		req = &fundRequest{Address: common.Address{0x42}, Ticket: ticket, Signature: signTicket(ticket, tm.rsa)}
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
	var res fundResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("unable to decode server response: %v", err)
	}
	_, _, err = client.TransactionByHash(context.Background(), res.Hash)
	if err != nil {
		t.Fatalf("unable to retreive tx: %v", err)
	}
}
