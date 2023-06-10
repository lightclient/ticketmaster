package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TicketMaster struct {
	db     *badger.DB
	rsa    *rsa.PrivateKey
	pk     *ecdsa.PrivateKey
	client *ethclient.Client
}

func (t *TicketMaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ticket":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.handleTicket(w, r)
	case "/fund":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.handleFund(w, r)
	default:
		http.NotFound(w, r)
	}
}

type ticketRequest struct {
	BlindedTicket   hexutil.Bytes `json:"ticket"`
	TransactionHash common.Hash   `json:"txhash"`
}

type ticketResponse struct {
	SignedBlindedTicket []hexutil.Bytes `json:"signed_blinded_ticket"`
}

func (t *TicketMaster) handleTicket(w http.ResponseWriter, r *http.Request) {
	var req ticketRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// verify req.TransactionHash
	var txdata []byte
	err = t.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(req.TransactionHash.Bytes())
		if err != nil {
			return err
		}
		val, err := item.ValueCopy(nil)
		txdata = append(txdata, val...)
		return err
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading txhash: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !bytes.Equal(txdata, req.BlindedTicket) {
		fmt.Fprintf(os.Stderr, "txdata does not match ticket: got %x, have %x\n", txdata, req.BlindedTicket)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Sign ticket.
	st := new(big.Int).SetBytes(req.BlindedTicket)
	st = st.Exp(st, t.rsa.D, t.rsa.N)

	fmt.Printf("valid request, signing ticket %x\n", st.Bytes())

	res := ticketResponse{SignedBlindedTicket: []hexutil.Bytes{st.Bytes()}}
	json.NewEncoder(w).Encode(res)
}

type fundRequest struct {
	Address   common.Address `json:"address"`
	Ticket    hexutil.Bytes  `json:"ticket"`
	Signature hexutil.Bytes  `json:"signature"`
}

type fundResponse struct {
	RawTransaction hexutil.Bytes `json:"signed_tx"`
	Hash           common.Hash   `json:"txhash"`
}

func (t *TicketMaster) handleFund(w http.ResponseWriter, r *http.Request) {
	var req fundRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check the signature is from us
	sig := big.NewInt(0).SetBytes(req.Signature)
	got := sig.Exp(sig, big.NewInt(int64(t.rsa.PublicKey.E)), t.rsa.N)
	want := sha256.Sum256(req.Ticket)
	if !bytes.Equal(got.Bytes(), want[:]) {
		log.Println("invalid signature")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check that this signature hasn't already been used
	var alreadyused bool
	err = t.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(append([]byte("sig"), req.Signature...))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err == nil {
			alreadyused = true
		}
		return err
	})
	if err != nil {
		log.Printf("error reading the signature table: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if alreadyused {
		log.Println("signature was already used")
		w.WriteHeader(http.StatusAlreadyReported)
		return
	}

	// Create the transaction
	nonce, err := t.client.NonceAt(context.Background(), crypto.PubkeyToAddress(t.pk.PublicKey), nil)
	if err != nil {
		log.Printf("failed to retrieve nonce: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	amount := big.NewInt(ticketCostMinusFee)
	gasLimit := uint64(txGasLimit)
	gasPrice := big.NewInt(20000000000) // 20 gwei

	tx := types.NewTransaction(nonce, req.Address, amount, gasLimit, gasPrice, nil)

	signer := types.NewEIP155Signer(big.NewInt(11155111))
	signedTx, _ := types.SignTx(tx, signer, t.pk)

	var buf bytes.Buffer
	if err = signedTx.EncodeRLP(&buf); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Store the signature
	err = t.db.Update(func(txn *badger.Txn) error {
		return txn.Set(append([]byte("sig"), req.Signature...), []byte{1})
	})
	if err != nil {
		log.Printf("error writing the signature table: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err = t.client.SendTransaction(context.Background(), signedTx); err != nil {
		log.Printf("error sending transaction: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := fundResponse{RawTransaction: buf.Bytes(), Hash: signedTx.Hash()}
	json.NewEncoder(w).Encode(res)
}
