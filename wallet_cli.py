# wallet_cli.py
import os
import asyncio
import json
import sys
import websockets
import time
import hashlib
from penercoin_hd import HDWallet

PASSWORD = "notsecret!"
KEYSTORE_PATH = "my_wallet.json"
DEFAULT_NODE_URL = "ws://localhost:8765" # Domyślny węzeł, do którego wysyłamy transakcje

def get_wallet() -> HDWallet:
    """Wczytuje portfel z pliku lub tworzy nowy, jeśli nie istnieje."""
    if os.path.exists(KEYSTORE_PATH):
        print(f"Loading wallet from {KEYSTORE_PATH}...")
        try:
            wallet = HDWallet.load_keystore(KEYSTORE_PATH, PASSWORD)
            print("Wallet loaded.")
            return wallet
        except Exception as e:
            print(f"Failed to load wallet (wrong password?): {e}")
            sys.exit(1)
    else:
        print("No wallet found. Generating new wallet...")
        wallet = HDWallet.generate()
        addr = wallet.generate_next_address(0)
        print(f"New wallet generated and saved to {KEYSTORE_PATH}")
        print(f"Your first address (m/0/0): {addr}")
        wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
        return wallet

async def send_transaction(wallet: HDWallet, node_url: str, recipient: str, amount: int):
    """Tworzy, podpisuje i wysyła transakcję do węzła."""
    
    # Użyjmy pierwszego adresu jako nadawcy
    sender_path = "m/0/0"
    sender_address = wallet.get_address(sender_path)
    
    # 1. Przygotuj dane transakcji
    tx_data = {
        "from": sender_address,
        "to": recipient,
        "amount": amount,
        "timestamp": time.time()
    }
    
    # 2. Oblicz hash danych transakcji (to jest "wiadomość" do podpisania)
    tx_string = json.dumps(tx_data, sort_keys=True)
    tx_hash_bytes = hashlib.sha256(tx_string.encode()).digest()
    
    # 3. Podpisz hash kluczem prywatnym
    signature_hex = wallet.sign_with_path(sender_path, tx_hash_bytes)
    
    # 4. Zdobądź klucz publiczny do weryfikacji
    # Musimy wysłać nieskompresowany klucz, aby węzły mogły go zweryfikować
    pubkey_uncompressed_hex = wallet.get_public_key_uncompressed_hex(sender_path)
    
    # 5. Skompletuj pełną transakcję
    full_tx_payload = {
        "tx_data": tx_data,
        "signature": signature_hex,
        "sender_pubkey": pubkey_uncompressed_hex
    }
    
    # 6. Przygotuj wiadomość dla węzła P2P
    message = json.dumps({"type": "TRANSACTION", "data": full_tx_payload})

    print(f"\n[Wallet] Connecting to node {node_url}...")
    try:
        async with websockets.connect(node_url) as ws:
            await ws.send(message)
            print(f"[Wallet] Sent transaction to node:")
            print(json.dumps(tx_data, indent=2))
            print(f"  Signature: {signature_hex[:10]}...")
    except Exception as e:
        print(f"[Wallet] Error sending transaction: {e}")

def show_addresses(wallet: HDWallet):
    print("\n--- Your Addresses ---")
    used = wallet.get_used_addresses()
    if not used:
        print("No addresses generated yet.")
    for addr in used:
        print(f"- {addr}")
    print(f"Next index: {wallet.get_next_index(0)}")

def generate_new_address(wallet: HDWallet):
    addr = wallet.generate_next_address(0)
    wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
    print(f"\nNew address generated and saved: {addr}")

async def main_cli():
    if len(sys.argv) < 2:
        print("Usage: python wallet_cli.py <command>")
        print("Commands:")
        print("  info        - Show wallet addresses and info")
        print("  gen_addr    - Generate a new address")
        print("  send <to_addr> <amount> [node_url] - Send a transaction")
        sys.exit(1)

    command = sys.argv[1]
    wallet = get_wallet()

    if command == "info":
        show_addresses(wallet)
        
    elif command == "gen_addr":
        generate_new_address(wallet)
        
    elif command == "send":
        if len(sys.argv) < 4:
            print("Usage: python wallet_cli.py send <to_addr> <amount> [node_url]")
            sys.exit(1)
        
        recipient = sys.argv[2]
        amount = int(sys.argv[3])
        node_url = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_NODE_URL
        
        await send_transaction(wallet, node_url, recipient, amount)
        
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    asyncio.run(main_cli())