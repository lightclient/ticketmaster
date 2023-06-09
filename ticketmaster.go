package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type TicketMaster struct {
	db  *badger.DB
	rsa *rsa.PrivateKey
	pk  *ecdsa.PrivateKey
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
	SignedBlindedTicket hexutil.Bytes `json:"signed_blinded_ticket"`
}

func (t *TicketMaster) handleTicket(w http.ResponseWriter, r *http.Request) {
	var req ticketRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
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
		fmt.Fprintf(os.Stderr, "error reading txhash: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !bytes.Equal(txdata, req.BlindedTicket) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Sign ticket.
	st := new(big.Int).SetBytes(req.BlindedTicket)
	st = st.Exp(st, t.rsa.D, t.rsa.N)

	res := ticketResponse{SignedBlindedTicket: st.Bytes()}
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(nil)
}
