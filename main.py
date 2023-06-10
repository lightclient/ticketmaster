import os
import re
import time
import json
import requests
import argparse
import datetime
from web3 import Web3
from termcolor import colored
from Crypto.Hash import SHA256
from eth_account import Account
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes


SIG_STORE_LOCATION = ".tmp/signatures.txt"
BLINDING_FACTOR_STORE_LOCATION = ".tmp/blinding_factor.txt"
COORDINATOR_ADDRESS = "0x523e0ad785F4A5390F1d698925C0A9f0a3634a2a"
COORDINATOR_TICKET_ENDPOINT = "<COORDINATOR-ENDPOINT>/buy"
COORDINATOR_FUND_ENDPOINT   = "<COORDINATOR-ENDPOINT>/redeem"
RSA_PUBKEY_COORDINATOR_N = 5298298849726832783480702623739365712909275778208202590983572003319847345109612129789926378138605185209390376978905967928561347051141720164846688116989155258132811944010953079331880003228076131682749758671949294314396190174282105918775939796358947990799544051435316039127164440257857273823914099730160860613636863800104038047747816997909051822182705416524526413348248233513194282060574138194668840723469334379309052306992267647880550362341800078655160304565220789444570530118230031950492099297182896961955734858657361978694484215313163896858046753600941442620701244926648096487778686515803184041572305341460082689686004443337882356867413569627545730753243185572419010152530479778647783326889171929469836992299259057631677030741066392648804381969930535663189178930116768769478725396929431738899682844919452306104577738592980824482232004985075595751489419627224973647093442213850935742083574719529134978089818021438156127336201
RSA_PUBKEY_COORDINATOR_E = 65537
TICKET_SIZE_IN_ETH = 0.01
GAS_IN_GWEI = 50
HEADERS = {'Content-Type': 'application/json'}

def generate_ticket():
    return bytes_to_long(SHA256.new(get_random_bytes(256)).digest())

def generate_random_tickets(nr):
    return [generate_ticket() for i in range(nr)]

def get_RSA_pubkey_of_coordinator(n, e):
    return RSA.construct((n, e))

def get_random_blinding_factor(COORDINATOR_RSA_PUBKEY):
    return bytes_to_long(get_random_bytes(256)) % COORDINATOR_RSA_PUBKEY.n

def store_blinding_factor_locally(blinding_factor):
    niceprint(f"Storing blinding_factor locally to {BLINDING_FACTOR_STORE_LOCATION}...")
    if not os.path.isdir(".tmp"):
        os.mkdir(".tmp")
    with open(BLINDING_FACTOR_STORE_LOCATION, "w") as file:
        file.write(str(blinding_factor))

def retrieve_blinding_factor():
    niceprint("Retrieving blinding factor...")
    try:
        with open(BLINDING_FACTOR_STORE_LOCATION, "r") as file:
            blinding_factor = int(file.read().strip())
        niceprint("Blinding factor found locally: ", blinding_factor)
        
    except:
        blinding_factor = get_random_blinding_factor(COORDINATOR_RSA_PUBKEY)
        niceprint("Blinding factor generated: ", blinding_factor)
        store_blinding_factor_locally(blinding_factor)
    return blinding_factor

def blind_tickets(unblinded_tickets, blinding_factor):
    niceprint("Blinding ticket(s)...")
    return [(
        ticket * pow(blinding_factor, 
                               COORDINATOR_RSA_PUBKEY.e, 
                               COORDINATOR_RSA_PUBKEY.n
                              )
    ) % COORDINATOR_RSA_PUBKEY.n for ticket in unblinded_tickets]

def prepare_blinded_tickets(blinded_tickets):
    niceprint("Prepare blinded ticket(s)...")
    calldata = ""
    apirequest = ""
    for btk in blinded_tickets:
        calldata += w3.toHex(btk)[2:]
        apirequest += w3.toHex(btk) + ","
    calldata = "0x" + calldata
    apirequest = apirequest[:-1]
    return calldata, apirequest
    

def unblind_tickets(signed_blinded_tickets, blinding_factor):
    niceprint("Unblinding ticket(s)...")
    return [
        (signed_blinded_ticket * inverse(blinding_factor, COORDINATOR_RSA_PUBKEY.n)) % COORDINATOR_RSA_PUBKEY.n 
    for signed_blinded_ticket in signed_blinded_tickets]

def verify_unblinded_ticket(signature, unblinded_ticket):
    niceprint("verifying unblinded ticket(s)...")
    assert pow(signature, COORDINATOR_RSA_PUBKEY.e, COORDINATOR_RSA_PUBKEY.n) == unblinded_ticket
    return

def generate_tx(user_account, calldata):
    return {
        'to': COORDINATOR_ADDRESS,  
        'value': TICKET_SIZE,  
        'gas': 100000,
        'gasPrice': GAS_PRICE,
        'nonce': w3.eth.getTransactionCount(user_account.address),  
        'chainId': 11155111,
        'data': calldata
    }

def sign_tx(tx, user_private_key):
    return w3.eth.account.sign_transaction(tx, user_private_key)

def send_tx(signed_tx):
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    niceprint(f"Transaction broadcasted with hash: {tx_hash.hex()}")
    return tx_hash.hex()
 
def transact(user_account, calldata):
    tx = generate_tx(user_account, calldata)
    signed_tx = sign_tx(tx, user_account.privateKey)
    tx_hash = send_tx(signed_tx)
    receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    # Check if the transaction was successful
    if receipt['status']:
        niceprint("Transaction was successful.")
    else:
        niceprint("Transaction failed.")
    return tx_hash
    
def send_blinded_ticket_to_coordinator(ticketdata, txhash):
    '''send the blinded ticket and txhash to the coordinator and receive a signature back'''
    data = json.dumps({
        'ticket': ticketdata,
        'txhash': txhash
    })
    try:
        response = requests.post(COORDINATOR_TICKET_ENDPOINT, headers=HEADERS, data=data, timeout=120)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        niceprint('An error occurred:', str(e))
    else:
        try:
            response_data = response.json() 
            hex_string = response_data.get('signed_blinded_ticket')
            if hex_string:
                return [int(i, 16) for i in hex_string]  
            else:
                niceprint('No hex value found in the response')
        except json.JSONDecodeError:
            niceprint('An error occurred while parsing the response')
            
def store_coordinator_signatures_locally(tickets, signatures):
    if not os.path.isdir(".tmp"):
        os.mkdir(".tmp")
    knownlines = []
    try:
        with open(SIG_STORE_LOCATION, "r") as file:
            for line in file:
                knownlines.append(line.strip())

    except:
        pass
    with open(SIG_STORE_LOCATION, "a") as file:
        for ix, signature in enumerate(signatures):
            if signature not in knownlines:
                niceprint(f"Storing signature locally to {SIG_STORE_LOCATION}...")
                file.write(w3.toHex(tickets[ix]) + "," + w3.toHex(signature) + ",\n")
            
def load_coordinator_signatures(nr):
    niceprint(f"Loading {nr} signature(s)...")
    tickets = []
    signatures = []
    with open(SIG_STORE_LOCATION, "r") as file:
        for line in file:
            if ',claimed' not in line:
                tickets.append(line.strip().split(",")[0])
                signatures.append(line.strip().split(",")[1])
                if len(signatures) == nr:
                    return tickets, signatures

    if len(signatures) < nr:
        raise ValueError(f"Only {len(signatures)} valid signatures found, but {nr} was requested.")
        
def invalidate_used_coordinator_signatures(signatures):
    knownlines = []
    with open(SIG_STORE_LOCATION, "r") as file:
        for line in file:
            knownlines.append(line.strip())
                
    with open(SIG_STORE_LOCATION, "w") as file:
        for signature in knownlines:          
            if signature.split(",")[1] in signatures:
                niceprint(f"Invalidating used signature(s)...")
                signature += "claimed"
            file.write(signature + "\n")
        
def send_signature_to_coordinator(tickets, signatures, address):
    '''send the signature and address to the coordinator and receive a tx hash back'''
    
    ticketdata = ",".join([str(ticket) for ticket in tickets]).split(',')
    signaturedata = ",".join([str(signature) for signature in signatures]).split(',')
    
    data = json.dumps({
        "ticket": ticketdata,
        'signature': signaturedata,
        'address': address
    })
    niceprint("Sending data to coordinator: ", data)
    try:
        response = requests.post(COORDINATOR_FUND_ENDPOINT, headers=HEADERS, data=data, timeout=120)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        niceprint('An error occurred:', str(e))
    else:
        try:
            response_data = response.json() 
            tx_hash = response_data.get('txhash')
            if tx_hash.startswith("0x") and len(tx_hash) == 66:
                niceprint("Coordinator has funded the address: ", tx_hash)
                return tx_hash  
            else:
                niceprint('No valid tx hash found in the response')
                raise
        except json.JSONDecodeError:
            niceprint('An error occurred while parsing the response')

def load_account_from_private_key(private_key: str):
    try:
        account = w3.eth.account.privateKeyToAccount(private_key)
        return account

    except exceptions.InvalidAddress as e:
        niceprint(f"Invalid private key: {e}")
    except Exception as e:
        niceprint(f"An error occurred: {e}")
        
def print_ascii_art():
    print(colored(
        """
  ____             _____ _      _        _   _             
 / ___| __ _ ___  |_   _(_) ___| | _____| |_(_)_ __   __ _ 
| |  _ / _` / __|   | | | |/ __| |/ / _ \ __| | '_ \ / _` |
| |_| | (_| \__ \   | | | | (__|   <  __/ |_| | | | | (_| |
 \____|\__,_|___/   |_| |_|\___|_|\_\___|\__|_|_| |_|\__, |
                                                     |___/ 
"""
        , "green") + "\n\nby Toni Wahrstätter, lightclient & Guillaume Ballet")
    time.sleep(1)
    

def niceprint(*args):
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    message = ' '.join(str(arg)[0:100]+"..." if len(str(arg)) > 100 else str(arg) for arg in args)
    print(f"{current_time} " + colored("[INFO]", "green") + f" {message}")
    
def parse_cli_arguments():
    parser = argparse.ArgumentParser(description='Gas Fee Ticketing CLI')
    parser.add_argument('action', type=str,choices=['buy', 'redeem'], 
                        help='Action to be performed (choices: "buy", "redeem")')
    parser.add_argument('--private-key', '-privkey', type=str,
                        default=None, help='Your private key')
    parser.add_argument('--nr-of-tickets', '-nr', type=int,
                        default=1, help='Number of tickets (default: 1)')
    parser.add_argument('--rpc-endpoint', '-rpc', type=str,
                        default="http://localhost:8545", help='RPC Endpoint')
    parser.add_argument('--redeem-address', '-addr', type=str,
                        default=None, help='Redeem ')

    return parser.parse_args()

def handle_cli_arguments(args):
    if args.action == "buy" and args.private_key == None:
        args.private_key = input("Input a valid private key:\n") 
    
    if args.action == "redeem" and args.redeem_address == None:
        args.redeem_address = input("Input a valid address to redeem to:\n") 
        
    if args.rpc_endpoint == None:
        args.rpc_endpoint = input("Input your RPC endpoint:\n") 
    return args.action, args.private_key,  args.nr_of_tickets, args.redeem_address, args.rpc_endpoint

def handle_ticket_buy(NR_OF_TICKETS, PRIVATE_KEY):    
    global w3, GAS_PRICE, TICKET_SIZE
            
    w3 = Web3(Web3.HTTPProvider(RPC))
    if not w3.isConnected():
        niceprint("Failure with RPC endpoint")
        
    TICKET_SIZE = w3.toWei(TICKET_SIZE_IN_ETH, 'ether')
    GAS_PRICE = w3.toWei(GAS_IN_GWEI, 'gwei')
    ACCOUNT = load_account_from_private_key(PRIVATE_KEY)   
    niceprint(f"RPC Endpoint: {RPC}")
    niceprint(f"Account: {ACCOUNT.address}")
    niceprint(f"Private Key: {ACCOUNT.privateKey.hex()}")
    
    tickets = generate_random_tickets(NR_OF_TICKETS)
    niceprint("Random ticket(s) generated: ", tickets)
    
    blinding_factor = retrieve_blinding_factor()
    niceprint("Blinding factor retrieved: ", blinding_factor)
    
    blinded_tickets = blind_tickets(tickets, blinding_factor)
    niceprint("Ticket(s) blinded: ", blinded_tickets)
    calldata, api_data = prepare_blinded_tickets(blinded_tickets)    
    tx_hash = transact(ACCOUNT, calldata)
    signed_blinded_tickets = send_blinded_ticket_to_coordinator(api_data, tx_hash)
    signatures = unblind_tickets(signed_blinded_tickets, blinding_factor)
    niceprint("Signatures from coordinator: ", signatures)
    store_coordinator_signatures_locally(tickets, signatures)
    return tx_hash

def handle_ticket_redemption(NR_OF_TICKETS, ADDRESS):    
    tickets, signatures = load_coordinator_signatures(NR_OF_TICKETS)
    tx_hash = send_signature_to_coordinator(tickets, signatures, ADDRESS)
    invalidate_used_coordinator_signatures(signatures)
    return tx_hash
    
def main():
    global RPC, COORDINATOR_RSA_PUBKEY
    print_ascii_art()
    args = parse_cli_arguments()
    
    ACTION, PRIVATE_KEY, NR_OF_TICKETS, ADDRESS, RPC = handle_cli_arguments(args)
    niceprint(f"Number of Tickets to {ACTION}: {NR_OF_TICKETS}")
    niceprint(f"Ticket size: {TICKET_SIZE_IN_ETH} ETH")
    
    COORDINATOR_RSA_PUBKEY = get_RSA_pubkey_of_coordinator(
        RSA_PUBKEY_COORDINATOR_N, 
        RSA_PUBKEY_COORDINATOR_E
    )
    
    if ACTION == "buy":
        handle_ticket_buy(NR_OF_TICKETS, PRIVATE_KEY)
    elif ACTION == "redeem":
        handle_ticket_redemption(NR_OF_TICKETS, ADDRESS)
    

if __name__ == "__main__":
    main()