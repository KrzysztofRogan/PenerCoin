# wallet_cli.py
import os
import asyncio
import json
import sys
import websockets
import time
import hashlib
import requests
from typing import List, Dict, Any

from penercoin_hd import HDWallet

PASSWORD = "notsecret!"
KEYSTORE_PATH = "my_wallet.json"
DEFAULT_NODE_URL = "ws://localhost:8765" 
# Zakładamy, że API HTTP jest na porcie o 1000 wyższym
DEFAULT_API_URL = "http://localhost:9765"

def get_wallet() -> HDWallet:
    """Wczytuje portfel z pliku lub tworzy nowy."""
    if os.path.exists(KEYSTORE_PATH):
        try:
            wallet = HDWallet.load_keystore(KEYSTORE_PATH, PASSWORD)
            return wallet
        except Exception as e:
            print(f"Failed to load wallet: {e}")
            sys.exit(1)
    else:
        print("Generating new wallet...")
        wallet = HDWallet.generate()
        addr = wallet.generate_next_address(0)
        print(f"First address: {addr}")
        wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
        return wallet

def calculate_tx_hash(tx_ins: List[Dict], tx_outs: List[Dict]) -> str:
    """
    Musi działać DOKŁADNIE tak samo jak w blockchain.py.
    Służy do obliczenia ID transakcji, które podpisujemy.
    """
    # W blockchain.py hashujemy strukturę bez podpisów
    # tx_ins w blockchain.py zawiera obiekt, tu mamy słowniki.
    # Musimy odwzorować strukturę: {'tx_out_id': ..., 'tx_out_index': ...}
    
    clean_ins = [
        {'tx_out_id': inp['tx_out_id'], 'tx_out_index': inp['tx_out_index']}
        for inp in tx_ins
    ]
    
    tx_content = {
        "tx_ins": clean_ins,
        "tx_outs": tx_outs
    }
    tx_string = json.dumps(tx_content, sort_keys=True)
    return hashlib.sha256(tx_string.encode()).hexdigest()

def fetch_my_utxos(api_url: str, my_address: str) -> List[Dict]:
    """
    Pobiera cały łańcuch i mempool, aby znaleźć niewydane monety (UTXO).
    To symuluje logikę węzła po stronie klienta.
    """
    print(f"[Wallet] Fetching chain data from {api_url}...")
    try:
        chain_res = requests.get(f"{api_url}/chain")
        chain_data = chain_res.json()['chain']
        
        # 1. Znajdź wszystkie outputy skierowane do mnie
        my_utxos = [] # Format: {'tx_id': str, 'index': int, 'amount': int}
        
        # Słownik zużytych inputów: {(tx_id, index): True}
        spent_outputs = set()

        all_txs = []
        # Zbieramy transakcje z bloków
        for block in chain_data:
            for tx in block['transactions']:
                all_txs.append(tx)
        
        # Opcjonalnie: Zbieramy transakcje z mempoola (żeby nie wydać dwa razy tego samego)
        try:
            mempool_res = requests.get(f"{api_url}/mempool")
            mempool_data = mempool_res.json()
            all_txs.extend(mempool_data)
        except Exception:
            print("[Wallet] Warning: Could not fetch mempool.")

        # 2. Analiza historii - co dostałem, a co wydałem
        for tx in all_txs:
            # Rejestrujemy zużycie (Inputs)
            for tx_in in tx['tx_ins']:
                # Input format: {'tx_out_id': ..., 'tx_out_index': ...}
                spent_key = (tx_in['tx_out_id'], tx_in['tx_out_index'])
                spent_outputs.add(spent_key)
        
        for tx in all_txs:
            # Szukamy wpływów (Outputs)
            tx_id = tx.get('id')
            if not tx_id and 'hash' in tx: tx_id = tx['hash'] # Kompatybilność nazw

            for idx, tx_out in enumerate(tx['tx_outs']):
                if tx_out['address'] == my_address:
                    # Sprawdzamy czy nie zostało to już wydane
                    if (tx_id, idx) not in spent_outputs:
                        my_utxos.append({
                            "tx_out_id": tx_id,
                            "tx_out_index": idx,
                            "amount": tx_out['amount']
                        })
                        
        return my_utxos

    except Exception as e:
        print(f"[Wallet] Error fetching UTXOs: {e}")
        return []

async def send_transaction(wallet: HDWallet, node_ws_url: str, recipient: str, amount: int):
    # Ustalamy port API na podstawie portu WS (WS port + 1000)
    # np. ws://localhost:8765 -> http://localhost:9765
    try:
        base_url = node_ws_url.replace("ws://", "http://").replace("wss://", "https://")
        port = int(base_url.split(":")[-1])
        api_url = base_url.rsplit(":", 1)[0] + f":{port + 1000}"
    except:
        api_url = DEFAULT_API_URL

    sender_path = "m/0/0"
    sender_address = wallet.get_address(sender_path)
    
    # 1. Pobierz UTXO (nasze dostępne monety)
    utxos = fetch_my_utxos(api_url, sender_address)
    current_balance = sum(u['amount'] for u in utxos)
    
    print(f"[Wallet] Address: {sender_address}")
    print(f"[Wallet] Balance: {current_balance} coins")
    print(f"[Wallet] UTXOs found: {len(utxos)}")

    if current_balance < amount:
        print(f"[Wallet] Error: Insufficient funds. You have {current_balance}, trying to send {amount}.")
        return

    # 2. Wybierz monety do wydania
    inputs = []
    input_sum = 0
    for utxo in utxos:
        inputs.append({
            "tx_out_id": utxo['tx_out_id'],
            "tx_out_index": utxo['tx_out_index'],
            "signature": "" # Placeholder, podpiszemy później
        })
        input_sum += utxo['amount']
        if input_sum >= amount:
            break
            
    # 3. Oblicz resztę (Change)
    change = input_sum - amount
    
    outputs = [
        {"address": recipient, "amount": amount}
    ]
    if change > 0:
        outputs.append({"address": sender_address, "amount": change})
        print(f"[Wallet] Change to self: {change}")

    # 4. Podpisz transakcję
    # W modelu UTXO zazwyczaj podpisuje się każdy input osobno.
    # Podpisujemy hash całej transakcji (bez podpisów).
    
    tx_hash_hex = calculate_tx_hash(inputs, outputs)
    tx_hash_bytes = bytes.fromhex(tx_hash_hex)
    
    # Generujemy podpis dla każdego inputu
    # (W tym prostym modelu zakładamy, że wszystkie UTXO należą do jednego klucza m/0/0)
    signature = wallet.sign_with_path(sender_path, tx_hash_bytes)
    
    # Wypełniamy pole signature w inputach
    for inp in inputs:
        inp['signature'] = signature

    # 5. Złóż payload
    full_tx_payload = {
        "id": tx_hash_hex,
        "tx_ins": inputs,
        "tx_outs": outputs
    }

    message = json.dumps({"type": "TRANSACTION", "data": full_tx_payload})

    print(f"\n[Wallet] Connecting to node {node_ws_url}...")
    try:
        async with websockets.connect(node_ws_url) as ws:
            await ws.send(message)
            print(f"[Wallet] Transaction sent! ID: {tx_hash_hex}")
    except Exception as e:
        print(f"[Wallet] Connection error: {e}")


def main_cli_sync():
    # Wrapper synchroniczny dla argparse, ale async dla logiki
    if len(sys.argv) < 2:
        print("Usage: python wallet_cli.py <command>")
        print("Commands:")
        print("  gen_addr    - Generate a new address")
        print("  balance [api_url] - Check balance via API")
        print("  send <to_addr> <amount> [node_ws_url] - Send transaction")
        sys.exit(1)

    command = sys.argv[1]
    wallet = get_wallet()

    if command == "gen_addr":
        addr = wallet.generate_next_address(0)
        wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
        print(f"New address: {addr}")

    elif command == "send":
        if len(sys.argv) < 4:
            print("Usage: ... send <to> <amount> [ws_url]")
            sys.exit(1)
        recipient = sys.argv[2]
        amount = int(sys.argv[3])
        node_url = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_NODE_URL
        
        asyncio.run(send_transaction(wallet, node_url, recipient, amount))

    elif command == "balance":
        # Proste sprawdzenie salda
        addr = wallet.get_address("m/0/0")
        api_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_API_URL
        utxos = fetch_my_utxos(api_url, addr)
        print(f"Address: {addr}")
        print(f"Total Balance: {sum(u['amount'] for u in utxos)}")

    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main_cli_sync()