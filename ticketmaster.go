package main

import (
	"bytes"
	"context"
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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

const (
	ticketCost         = 10_000_000_000_000_000
	txFee              = 0
	ticketCostMinusFee = ticketCost - txFee
)

// TicketMaster manages the ticket collection, responding to http requests to
// buy and redeem.
type TicketMaster struct {
	db     *badger.DB
	rsa    *rsa.PrivateKey
	sk     *ecdsa.PrivateKey
	client *ethclient.Client
}

func (t *TicketMaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/buy":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.handleBuy(w, r)
	case "/redeem":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.handleRedeem(w, r)
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

// handleBuy allows a caller to request a the coordinator to process its ticket
// purchase which was initiated on-chain.
func (t *TicketMaster) handleBuy(w http.ResponseWriter, r *http.Request) {
	var req ticketRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Error("unable to decode ticketRequest", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify we've seen the transaction hash from the caller.
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
		// Ticket not found, or error reading database.
		fmt.Fprintf(os.Stderr, "error reading txhash: %v\n", err)
		log.Error("buy request for unknown txhash", "hash", req.TransactionHash, "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Verify the blinded ticket matches the ticket in the calldata.
	if !bytes.Equal(txdata, req.BlindedTicket) {
		log.Error("txdata does not match ticket", "got", txdata, "have", req.BlindedTicket)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Sign blinded ticket.
	sbTicket := signBlindedTicket(t.rsa, req.BlindedTicket)
	log.Info("recieved valid buy request, signing blinded ticket")

	// Return signed blinded ticket.
	res := ticketResponse{SignedBlindedTicket: []hexutil.Bytes{sbTicket}}
	json.NewEncoder(w).Encode(res)
}

type redeemRequest struct {
	Address       common.Address  `json:"address"`
	HashedTickets []hexutil.Bytes `json:"tickets"`
	Signatures    []hexutil.Bytes `json:"signatures"`
}

type fundResponse struct {
	RawTransaction hexutil.Bytes `json:"signed_tx"`
	Hash           common.Hash   `json:"txhash"`
}

// handleRedeem allows a ticket owner to redeem their ticket and sends the
// associated funds to the requested account.
func (t *TicketMaster) handleRedeem(w http.ResponseWriter, r *http.Request) {
	var req redeemRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Error("error decoding redeemRequest", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify signature.
	validTickets := 0
	for i, ticket := range req.HashedTickets {
		// Verify signature.
		if !verifySignature(&t.rsa.PublicKey, req.Signatures[i], ticket) {
			log.Error("invalid signature for redeption")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if signature has been redeemed.
		var redeemed bool
		err = t.db.View(func(txn *badger.Txn) error {
			_, err := txn.Get(append([]byte("sig"), req.Signatures[i]...))
			if err == badger.ErrKeyNotFound {
				// Key is good.
				return nil
			}
			// Key found, already used.
			if err == nil {
				redeemed = true
			}
			return err
		})
		if err != nil {
			log.Error("failed to read the signature table", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if redeemed {
			log.Error("redeem attempted on already used signature")
			w.WriteHeader(http.StatusAlreadyReported)
			return
		}
		validTickets += 1
	}

	// Store the signature to avoid replays.
	for _, sig := range req.Signatures {
		err = t.db.Update(func(txn *badger.Txn) error {
			return txn.Set(append([]byte("sig"), sig...), []byte{1})
		})
		if err != nil {
			log.Error("error writing the signature table", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Create transaction.
	tx, err := t.createTx(req.Address, validTickets)
	if err != nil {
		log.Error("error creating redemption tx", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Send transaction.
	if err = t.client.SendTransaction(context.Background(), tx); err != nil {
		log.Error("error sending redemption transaction", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Info("ticket redeemed successfully", "hash", tx.Hash())
	res := fundResponse{RawTransaction: nil, Hash: tx.Hash()}
	json.NewEncoder(w).Encode(res)
}

// createTx creates a transaction funding the requested account.
func (t *TicketMaster) createTx(to common.Address, tickets int) (*types.Transaction, error) {
	ctx := context.Background()
	// Get nonce.
	nonce, err := t.client.NonceAt(ctx, crypto.PubkeyToAddress(t.sk.PublicKey), nil)
	if err != nil {
		return nil, err
	}
	// Get block to get recent base fee.
	block, err := t.client.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	// Create and sign tx.
	tipCap := big.NewInt(42) // god bless the block producer
	feeCap := max(block.BaseFee().Mul(block.BaseFee(), common.Big2), tipCap)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   params.SepoliaChainConfig.ChainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       params.TxGas, // no free lunch
		To:        &to,
		Value:     big.NewInt(ticketCostMinusFee * int64(tickets)),
	})
	signer := types.LatestSigner(params.SepoliaChainConfig)
	return types.SignTx(tx, signer, t.sk)
}

func max(x, y *big.Int) *big.Int {
	if x.Cmp(y) == -1 {
		return y
	}
	return x
}
