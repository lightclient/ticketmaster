# TicketMaster

_an eth prague 2023 submission_

This repo contains the tools needed for a [Gas Ticketing](https://hackmd.io/@Nerolation/rkp8LyRUh) PoC. This includes a Python CLI and the code for the coordinator in Go, the `ticketmaster`.

The `ticketmaster` is a coordinator that allows users to purchase "tickets"
that can later be "redeemed" to fund a [stealth account][1]. The mechanism uses
blind signatures so the coordinator is unable to link individual tickets with
redeemers. It is an implementation of Toni Wahrstätter's post ["Gas
Ticketing"][2].

![this is fine](https://github.com/nerolation/Ethereum-ticket-system/assets/51536394/a509950b-d5dd-4093-8995-572e9cb8081e)


---


## Gas Ticketing CLI

The CLI provides two main functionalities:

1. **Buy**: Purchase gas fee tickets.
2. **Redeem**: Redeem previously purchased gas fee tickets.

Each ticket bought or redeemed carries a unique signature. The CLI also provides utilities for generating blinding factors, blinding/unblinding tickets and storing, loading, and invalidating these tickets locally.

## Installation

You will need Python 3.7+ to run this CLI. If you have the appropriate version of Python, you can install the CLI by cloning the GitHub repository.

```bash
git clone https://github.com/lightclient/ticketmaster.git
cd ticketmaster
pip install -r requirements.txt
```

## Usage

### Installation

The CLI is invoked from the command line with the following syntax:

```bash
python main.py [action] --private-key [private_key] --nr-of-tickets [number_of_tickets] --rpc-endpoint [rpc_endpoint] --redeem-address [redeem_address]
```

### Parameters


- **[action]**: This mandatory parameter defines the action to be performed. It can either be `buy` to purchase gas fee tickets, or `redeem` to redeem previously purchased tickets.

- **--private-key [private_key]**: This optional parameter is required when buying tickets. It should be the private key of the Ethereum account from which funds will be drawn for purchasing tickets.

- **--nr-of-tickets [number_of_tickets]**: This optional parameter specifies the number of tickets to be purchased or redeemed. It defaults to 1.

- **--rpc-endpoint [rpc_endpoint]**: This optional parameter specifies the RPC Endpoint to which the CLI will connect. If not specified, it defaults to `http://localhost:8545`.

- **--redeem-address [redeem_address]**: This optional parameter is required when redeeming tickets. It should be the Ethereum address to which the redeemed funds will be transferred.


### Examples

#### Buying tickets:
To buy tickets, use the buy action and provide your private key. In this example, we'll buy 1 tickets.

`python main.py buy --private-key YOUR_PRIVATE_KEY --nr-of-tickets 1`

#### Redeeming tickets:
To redeem tickets, use the redeem action and provide the Ethereum address where the funds should be sent. In this example, we'll redeem 1 tickets.

`python main.py redeem --redeem-address YOUR_ETHER_ADDRESS --nr-of-tickets 1`

Custom RPC endpoint:
You may also specify a custom RPC endpoint using the --rpc-endpoint flag. If not specified, the default value is http://localhost:8545.

`python main.py buy --private-key YOUR_PRIVATE_KEY --nr-of-tickets 1 --rpc-endpoint YOUR_RPC_ENDPOINT`

*Note that this repo is only supposed to be a PoC (that was developed within 2 days) and may contains bugs, inefficiencies and security vulnerabilities.*

[1]: https://vitalik.ca/general/2023/01/20/stealth.html
[2]: https://hackmd.io/@Nerolation/rkp8LyRUh
