import os
import asyncio
import json
import sys
import websockets
from penercoin_hd import HDWallet

PASSWORD = "notsecret!"
NUM_ADDRESSES_INITIAL = 3
NUM_ADDRESSES_NEW = 2

async def send_transaction(node_url: str, amount: int = 10):
    tx = {
        "from": "first_recipient",
        "to": "second_recipient",
        "amount": amount
    }

    tx["signature"] = "signature"

    message = json.dumps({"type": "TRANSACTION", "data": tx})

    async with websockets.connect(node_url) as ws:
        await ws.send(message)
        print(f"[Wallet] Sent transaction to {node_url}")
        print(f"[Wallet] TX data: {json.dumps(tx, indent=2)}")

def main():
    print("=== PenerCoin HD Wallet + Keystore Test ===\n")

    w = HDWallet.generate()
    print("Wallet generated.")

    print(f"\nGenerating {NUM_ADDRESSES_INITIAL} initial addresses:")
    for i in range(NUM_ADDRESSES_INITIAL):
        addr = w.generate_next_address()
        path = f"m/0/{i}"
        priv_hex = w.get_private_key_hex(path)
        pub_hex = w.get_public_key_compressed_hex(path)
        print(f"{i}: {addr}")
        print(f"  Private key: {priv_hex}")
        print(f"  Public key : {pub_hex}")

    keystore_path = os.path.join(os.getcwd(), "wallet_keystore2.json")
    w.save_keystore(keystore_path, PASSWORD)
    print(f"\nKeystore saved to {keystore_path}")

    w_loaded = HDWallet.load_keystore(keystore_path, PASSWORD)
    print("\nWallet loaded from keystore.")
    print("Next index (chain 0):", w_loaded.get_next_index(0))
    print("Used addresses:", w_loaded.get_used_addresses())

    print(f"\nGenerating {NUM_ADDRESSES_NEW} new addresses after load:")
    for _ in range(NUM_ADDRESSES_NEW):
        addr = w_loaded.generate_next_address()
        print(addr)

    w_loaded.save_keystore(keystore_path, PASSWORD)
    print("\nUpdated keystore saved with new addresses.")
    



if __name__ == "__main__":
    main()
    asyncio.run(send_transaction("ws://localhost:8767", 50))