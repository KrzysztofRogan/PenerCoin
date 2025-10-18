import asyncio
import json
import sys
import websockets
from wallet import Wallet


async def send_transaction(node_url: str, amount: int = 10):
    wallet = Wallet.generate()
    tx = {
        "from": wallet.public_key_hex(),
        "to": "recipient-public-key",
        "amount": amount
    }
    raw = json.dumps(tx)
    tx["signature"] = wallet.sign(raw.encode())

    message = json.dumps({"type": "TRANSACTION", "data": tx})

    async with websockets.connect(node_url) as ws:
        await ws.send(message)
        print(f"[Wallet] Sent transaction to {node_url}")
        print(f"[Wallet] TX data: {json.dumps(tx, indent=2)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: python demo.py ws://localhost:8765 [amount]")
        sys.exit(1)

    node_url = sys.argv[1]
    amount = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    asyncio.run(send_transaction(node_url, amount))
