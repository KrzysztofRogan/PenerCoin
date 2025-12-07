# node.py
import asyncio
import websockets
import json
import sys
from threading import Thread
import logging

from flask import Flask, jsonify
from blockchain import Blockchain, Transaction, Block

def run_flask_app(app, port):
    """Uruchamia serwer Flask na podanym porcie."""
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print(f"[API] Serwer HTTP API uruchomiony na http://localhost:{port}")
    app.run(host="0.0.0.0", port=port)


class Node:
    def __init__(self, port: int, peers=None, is_miner: bool = False, miner_address: str = None):
        self.port = port
        self.peers = peers or []
        self.server = None
        self.connections = set()
        
        # Inicjalizacja Blockchaina (cała logika jest wewnątrz)
        self.blockchain = Blockchain()
        
        self.is_miner = is_miner
        self.miner_address = miner_address
        if self.is_miner and not self.miner_address:
            print("[Node] Miner node must be started with a miner_address.")
            sys.exit(1)
        
        self.flask_app = self.create_flask_app()
        print(f"[Node:{self.port}] Initialized. Miner: {self.is_miner}")

    def create_flask_app(self):
        app = Flask(__name__)

        @app.route('/chain', methods=['GET'])
        def get_chain():
            chain_data = self.blockchain.get_chain_dict()
            return jsonify({
                "length": len(chain_data),
                "chain": chain_data
            })

        @app.route('/mempool', methods=['GET'])
        def get_mempool():
            return jsonify(self.blockchain.get_pending_tx_dict())
            
        @app.route('/status', methods=['GET'])
        def get_status():
            return jsonify({
                "port": self.port,
                "is_miner": self.is_miner,
                "block_height": self.blockchain.get_latest_block().index,
                "peers_connected": len(self.connections)
            })

        @app.route('/balance/<address>', methods=['GET'])
        def get_balance_endpoint(address):
            balance = self.blockchain.get_balance(address)
            return jsonify({
                "address": address,
                "balance": balance
            })
            
        return app

    async def start_server(self):
        async def handler(ws):
            self.connections.add(ws)
            try:
                await self.send_chain(ws)
                async for msg in ws:
                    await self.handle_message(ws, msg)
            except websockets.ConnectionClosed:
                pass
            finally:
                if ws in self.connections:
                    self.connections.remove(ws)

        self.server = await websockets.serve(handler, "localhost", self.port)
        print(f"[Node:{self.port}] Serwer WebSocket nasłuchuje na ws://localhost:{self.port}")

    async def connect_to_peers(self):
        for p in list(self.peers):
            try:
                ws = await websockets.connect(p)
                self.connections.add(ws)
                asyncio.create_task(self.receive_loop(ws))
                print(f"[Node:{self.port}] Połączono z peerem {p}")
                await ws.send(json.dumps({"type": "GET_CHAIN"}))
            except Exception as e:
                print(f"[Node:{self.port}] Nie można połączyć z {p}: {e}")

    async def receive_loop(self, ws):
        try:
            async for msg in ws:
                await self.handle_message(ws, msg)
        except websockets.ConnectionClosed:
            pass
        finally:
            if ws in self.connections:
                self.connections.remove(ws)

    async def handle_message(self, ws, raw_msg: str):
        try:
            msg = json.loads(raw_msg)
        except Exception:
            return

        t = msg.get("type")
        data = msg.get("data")

        if t == "TRANSACTION":
            try:
                tx = Transaction.from_dict(data)
                # Node tylko przekazuje do blockchaina i pyta "czy to nowość i czy ok?"
                if self.blockchain.add_transaction(tx):
                    await self.broadcast(raw_msg, exclude=ws)
            except Exception as e:
                print(f"[Node:{self.port}] Błąd TX: {e}")

        elif t == "NEW_BLOCK":
            try:
                block = Block.from_dict(data)
                # Node przekazuje blok do weryfikacji i dodania
                if self.blockchain.add_block(block):
                    await self.broadcast(raw_msg, exclude=ws)
            except Exception as e:
                print(f"[Node:{self.port}] Błąd BLOCK: {e}")
        
        elif t == "GET_CHAIN":
            await self.send_chain(ws)
            
        elif t == "CHAIN":
            # Cała logika "najdłuższy wygrywa" jest teraz w blockchain.replace_chain
            if self.blockchain.replace_chain(data):
                # Jeśli wymieniliśmy łańcuch, możemy opcjonalnie rozgłosić to dalej,
                # ale zazwyczaj to węzły same pytają o łańcuch.
                pass

    async def broadcast(self, message: str, exclude=None):
        for conn in list(self.connections):
            if conn is exclude:
                continue
            try:
                await conn.send(message)
            except Exception:
                pass

    async def miner_loop(self):
        while True:
            await asyncio.sleep(10)
            
            # Decyzję czy kopać podejmuje Node (lub logika biznesowa), 
            # ale wykonanie jest w blockchain.
            if not self.blockchain.pending_transactions:
                continue
                
            print(f"[Miner:{self.port}] Próba wykopania nowego bloku...")
            new_block = self.blockchain.mine_pending_transactions(self.miner_address)
            
            if new_block:
                print(f"[Miner:{self.port}] Wykopano blok #{new_block.index}! Rozgłaszanie...")
                msg = {
                    "type": "NEW_BLOCK",
                    "data": new_block.to_dict()
                }
                await self.broadcast(json.dumps(msg))

    async def send_chain(self, ws):
        try:
            # Pobieramy dane z blockchaina
            chain_data = self.blockchain.get_chain_dict()
            msg = {"type": "CHAIN", "data": chain_data}
            await ws.send(json.dumps(msg))
        except Exception as e:
            print(f"[Node:{self.port}] Błąd wysyłania łańcucha: {e}")

    async def run(self):
        await self.start_server()
        await asyncio.sleep(0.5)
        await self.connect_to_peers()
        
        if self.is_miner:
            asyncio.create_task(self.miner_loop())
            
        api_port = self.port + 1000
        api_thread = Thread(
            target=run_flask_app, 
            args=(self.flask_app, api_port), 
            daemon=True
        )
        api_thread.start()


async def main():
    if len(sys.argv) < 2:
        print("Usage: python node.py <port> [--miner <your_address>] [peer1_url] [peer2_url] ...")
        sys.exit(1)

    port = int(sys.argv[1])
    is_miner = False
    miner_address = None
    peers_start_index = 2

    if "--miner" in sys.argv:
        try:
            idx = sys.argv.index("--miner")
            miner_address = sys.argv[idx + 1]
            is_miner = True
            peers_start_index = idx + 2
            print(f"Startuję jako GÓRNIK. Adres: {miner_address}")
        except IndexError:
            sys.exit(1)
            
    peers = sys.argv[peers_start_index:]
    node = Node(port=port, peers=peers, is_miner=is_miner, miner_address=miner_address)
    await node.run()
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())