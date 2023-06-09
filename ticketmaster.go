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

// ServeHTTP handles the HTTP request
func (h *TicketMaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle the request
	switch r.URL.Path {
	case "/ticket":
		handleTicket(w, r)
	case "/fund":
		handleFund(w, r)
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

func handleTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req ticketRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	res := ticketResponse{SignedBlindedTicket: signedBlindedTicket}
	json.NewEncoder(w).Encode(res)
}

func handleFund(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req FundRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Perform necessary operations to generate the signed_tx and txhash
	signedTx, txhash := generateSignedTxAndTxHash(req.Ticket, req.Address)

	res := FundResponse{SignedTx: signedTx, TxHash: txhash}
	json.NewEncoder(w).Encode(res)
}
