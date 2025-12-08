# wallet_cli.py
import os
import asyncio
import json
import sys
import websockets
import time
import hashlib
import urllib.request
from penercoin_hd import HDWallet

PASSWORD = "notsecret!"
# Domyślna nazwa, jeśli nie podasz flagi -w
KEYSTORE_PATH = "my_wallet.json" 
DEFAULT_NODE_URL = "ws://localhost:6700"

def get_wallet() -> HDWallet:
    """Wczytuje portfel z pliku zdefiniowanego w KEYSTORE_PATH."""
    # Używamy globalnej zmiennej, która mogła zostać zmieniona przez argumenty
    global KEYSTORE_PATH
    
    if os.path.exists(KEYSTORE_PATH):
        print(f"[System] Ładowanie portfela z pliku: {KEYSTORE_PATH}")
        try:
            wallet = HDWallet.load_keystore(KEYSTORE_PATH, PASSWORD)
            return wallet
        except Exception as e:
            print(f"Nie udało się załadować portfela (złe hasło?): {e}")
            sys.exit(1)
    else:
        print(f"[System] Nie znaleziono {KEYSTORE_PATH}. Generowanie nowego portfela...")
        wallet = HDWallet.generate()
        addr = wallet.generate_next_address(0)
        print(f"Nowy portfel wygenerowany.")
        print(f"Twój pierwszy adres (m/0/0): {addr}")
        wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
        print(f"Zapisano do: {KEYSTORE_PATH}")
        return wallet

# W wallet_cli.py

async def send_transaction(wallet: HDWallet, node_ws_url: str, recipient: str, amount: int):
    sender_path = "m/0/0"
    sender_address = wallet.get_address(sender_path)
    
    print(f"Nadawca: {sender_address}")
    
    # 1. Pobierz aktualny NONCE z API HTTP węzła
    # Zakładamy, że API HTTP jest na porcie WS + 1000 (tak jest w node.py)
    try:
        # Parsowanie adresu URL, np. ws://localhost:6700 -> http://localhost:7700
        from urllib.parse import urlparse
        parsed = urlparse(node_ws_url)
        host = parsed.hostname
        ws_port = parsed.port
        if not ws_port: ws_port = 80 # fallback
        
        api_port = ws_port + 1000
        api_url = f"http://{host}:{api_port}/nonce/{sender_address}"
        
        print(f"[Wallet] Pobieranie nonce z {api_url}...")
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read().decode())
            nonce = data['nonce']
            print(f"[Wallet] Otrzymano Nonce: {nonce}")

    except Exception as e:
        print(f"[Wallet] Błąd pobierania nonce: {e}")
        print("Upewnij się, że węzeł działa i API HTTP jest dostępne.")
        return

# dodano nonce
    tx_data = {
        "from": sender_address,
        "to": recipient,
        "amount": amount,
        "nonce": nonce,   
        "timestamp": time.time()
    }
    
    tx_string = json.dumps(tx_data, sort_keys=True)
    tx_hash_bytes = hashlib.sha256(tx_string.encode()).digest()
    
    signature_hex = wallet.sign_with_path(sender_path, tx_hash_bytes)
    pubkey_uncompressed_hex = wallet.get_public_key_uncompressed_hex(sender_path)
    
    full_tx_payload = {
        "tx_data": tx_data,
        "signature": signature_hex,
        "sender_pubkey": pubkey_uncompressed_hex
    }
    
    message = json.dumps({"type": "TRANSACTION", "data": full_tx_payload})

    print(f"[Wallet] Łączenie z węzłem {node_ws_url}...")
    try:
        async with websockets.connect(node_ws_url) as ws:
            await ws.send(message)
            print(f"[Wallet] Transakcja wysłana pomyślnie!")
            print(json.dumps(tx_data, indent=2))
    except Exception as e:
        print(f"[Wallet] Błąd wysyłania: {e}")

def show_addresses(wallet: HDWallet):
    print(f"\n--- Adresy w portfelu ({KEYSTORE_PATH}) ---")
    used = wallet.get_used_addresses()
    if not used:
        print("Brak wygenerowanych adresów.")
    for addr in used:
        print(f"- {addr}")

def generate_new_address(wallet: HDWallet):
    addr = wallet.generate_next_address(0)
    wallet.save_keystore(KEYSTORE_PATH, PASSWORD)
    print(f"\nNowy adres wygenerowany i zapisany w {KEYSTORE_PATH}: {addr}")

async def main_cli():
    global KEYSTORE_PATH

    # --- NOWA LOGIKA OBSŁUGI PLIKÓW ---
    # Sprawdzamy czy użytkownik podał flagę -w <plik>
    if "-w" in sys.argv:
        try:
            idx = sys.argv.index("-w")
            # Pobieramy nazwę pliku
            custom_path = sys.argv[idx + 1]
            KEYSTORE_PATH = custom_path
            
            # Usuwamy -w i nazwę pliku z listy argumentów, 
            # żeby reszta kodu (sys.argv[1] itp.) działała po staremu
            del sys.argv[idx:idx+2]
        except IndexError:
            print("Błąd: Flaga -w wymaga podania nazwy pliku (np. -w alicja.json)")
            sys.exit(1)
    # -----------------------------------

    if len(sys.argv) < 2:
        print("Użycie: python wallet_cli.py [-w plik.json] <komenda>")
        print("Komendy:")
        print("  info        - Pokaż adresy")
        print("  gen_addr    - Wygeneruj nowy adres")
        print("  send <to_addr> <amount> [node_url] - Wyślij transakcję")
        sys.exit(1)

    command = sys.argv[1]
    wallet = get_wallet()

    if command == "info":
        show_addresses(wallet)
        
    elif command == "gen_addr":
        generate_new_address(wallet)
        
    elif command == "send":
        if len(sys.argv) < 4:
            print("Użycie: python wallet_cli.py [-w plik] send <to_addr> <amount> [node_url]")
            sys.exit(1)
        
        recipient = sys.argv[2]
        amount = int(sys.argv[3])
        node_url = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_NODE_URL
        
        await send_transaction(wallet, node_url, recipient, amount)
        
    else:
        print(f"Nieznana komenda: {command}")

if __name__ == "__main__":
    asyncio.run(main_cli())