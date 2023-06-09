package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/dgraph-io/badger/v3"
)

type TicketMaster struct {
	db *badger.DB
	pk *rsa.PrivateKey
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
	BlindedTicket   []byte `json:"ticket"`
	TransactionHash Hash   `json:"txhash"`
}

type ticketResponse struct {
	SignedBlindedTicket []byte `json:"signed_blinded_ticket"`
}

func (t *TicketMaster) handleTicket(w http.ResponseWriter, r *http.Request) {
	var req ticketRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	res := ticketResponse{SignedBlindedTicket: signTicket(t.pk, req.BlindedTicket)}
	json.NewEncoder(w).Encode(res)
}

type fundRequest struct {
	Address   Address `json:"address"`
	Ticket    []byte  `json:"ticket"`
	Signature []byte  `json:"signature"`
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
