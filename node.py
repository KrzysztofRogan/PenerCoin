# node.py
import asyncio
import websockets
import json
import sys
import time

# Importujemy naszą logikę blockchain
from blockchain import Blockchain, Transaction, Block
from typing import List, Dict, Any, Optional

## NOWOŚĆ: Importujemy Flask i Threading
from flask import Flask, jsonify
from threading import Thread
import logging

## NOWOŚĆ: Funkcja pomocnicza do uruchomienia Flaska w wątku
def run_flask_app(app, port):
    """Uruchamia serwer Flask na podanym porcie."""
    # Wyłączamy domyślne logowanie Flaska, aby nie zaśmiecać konsoli węzła
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
        self.known_peers = set(self.peers)
        
        # Każdy węzeł ma własną kopię łańcucha bloków
        self.blockchain = Blockchain()
        
        # Logika górnika
        self.is_miner = is_miner
        self.miner_address = miner_address
        if self.is_miner and not self.miner_address:
            print("[Node] Miner node must be started with a miner_address.")
            sys.exit(1)
        
        ## NOWOŚĆ: Tworzymy instancję aplikacji Flask
        self.flask_app = self.create_flask_app()
        
        print(f"[Node:{self.port}] Initialized. Miner: {self.is_miner}")

    ## NOWOŚĆ: Metoda tworząca aplikację Flask i jej endpointy
    def create_flask_app(self):
        app = Flask(__name__)

        @app.route('/chain', methods=['GET'])
        def get_chain():
            """Zwraca cały łańcuch bloków węzła w formacie JSON."""
            chain_data = [block.to_dict() for block in self.blockchain.chain]
            return jsonify({
                "length": len(chain_data),
                "chain": chain_data
            })

        @app.route('/mempool', methods=['GET'])
        def get_mempool():
            """Zwraca listę transakcji oczekujących na wykopanie."""
            tx_data = [tx.to_dict() for tx in self.blockchain.pending_transactions]
            return jsonify(tx_data)
            
        @app.route('/status', methods=['GET'])
        def get_status():
            """Zwraca podstawowy status węzła."""
            return jsonify({
                "port": self.port,
                "is_miner": self.is_miner,
                "block_height": self.blockchain.get_latest_block().index,
                "peers_connected": len(self.connections)
            })
            
        return app

    async def start_server(self):
        async def handler(ws):
            self.connections.add(ws)
            # print(f"[Node:{self.port}] New connection from {ws.remote_address}") # Mniej "hałasu"
            try:
                # Przy nowym połączeniu, wyślijmy mu nasz łańcuch
                await self.send_chain(ws)
                
                async for msg in ws:
                    await self.handle_message(ws, msg)
            except websockets.ConnectionClosed:
                # print(f"[Node:{self.port}] Connection closed from {ws.remote_address}")
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
                # Uruchom pętlę odbioru dla tego połączenia
                asyncio.create_task(self.receive_loop(ws))
                print(f"[Node:{self.port}] Połączono z peerem {p}")
                # Poproś o łańcuch od peera, do którego się łączysz
                await ws.send(json.dumps({"type": "GET_CHAIN"}))
            except Exception as e:
                print(f"[Node:{self.port}] Nie można połączyć z {p}: {e}")

    async def receive_loop(self, ws):
        """Pętla do odbierania wiadomości od peerów, z którymi się połączyliśmy."""
        try:
            async for msg in ws:
                await self.handle_message(ws, msg)
        except websockets.ConnectionClosed:
            # print(f"[Node:{self.port}] Utracono połączenie z peerem")
            pass
        finally:
            if ws in self.connections:
                self.connections.remove(ws)

    async def handle_message(self, ws, raw_msg: str):
        try:
            msg = json.loads(raw_msg)
        except Exception:
            print(f"[Node:{self.port}] Otrzymano niepoprawny JSON.")
            return

        t = msg.get("type")
        data = msg.get("data")
        # print(f"[Node:{self.port}] Received message type: {t}")

        if t == "TRANSACTION":
            try:
                # Sprawdźmy, czy już mamy tę transakcję
                tx = Transaction.from_dict(data)
                if tx.tx_hash in [t.tx_hash for t in self.blockchain.pending_transactions]:
                    return # Już ją mamy, ignoruj
                    
                if self.blockchain.add_transaction(tx):
                    # Transakcja jest poprawna, rozgłoś ją dalej
                    await self.broadcast(raw_msg, exclude=ws)
            except Exception as e:
                print(f"[Node:{self.port}] Błąd przetwarzania TRANSAKCJI: {e}")

        elif t == "NEW_BLOCK":
            try:
                block = Block.from_dict(data)
                # Sprawdź, czy już mamy ten blok
                if block.hash == self.blockchain.get_latest_block().hash:
                    return # Już go mamy
                
                if self.blockchain.add_block(block):
                    # Blok jest poprawny, rozgłoś go dalej
                    await self.broadcast(raw_msg, exclude=ws)
            except Exception as e:
                print(f"[Node:{self.port}] Błąd przetwarzania NOWEGO BLOKU: {e}")
        
        elif t == "GET_CHAIN":
            # Ktoś prosi o nasz łańcuch
            await self.send_chain(ws)
            
        elif t == "CHAIN":
            # Otrzymaliśmy pełny łańcuch od peera
            self.handle_received_chain(data)

        elif t == "PING":
            await ws.send(json.dumps({"type": "PONG"}))
        elif t == "PONG":
            pass
        else:
            print(f"[Node:{self.port}] Nieznany typ wiadomości: {t}")

    async def broadcast(self, message: str, exclude=None):
        """Rozgłasza wiadomość do wszystkich połączonych peerów."""
        # Kopiujemy listę, na wypadek gdyby self.connections zmieniło się w trakcie
        for conn in list(self.connections):
            if conn is exclude:
                continue
            try:
                await conn.send(message)
            except Exception:
                # Peer mógł się rozłączyć
                pass

    async def miner_loop(self):
        """Pętla dla górnika - próbuje kopać nowy blok co 10 sekund."""
        while True:
            await asyncio.sleep(10)
            
            if not self.blockchain.pending_transactions:
                # print("[Miner] No transactions to mine.")
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
        """Wysyła pełny łańcuch bloków do danego websocket."""
        try:
            chain_data = [block.to_dict() for block in self.blockchain.chain]
            msg = {"type": "CHAIN", "data": chain_data}
            await ws.send(json.dumps(msg))
        except Exception as e:
            print(f"[Node:{self.port}] Błąd wysyłania łańcucha: {e}")

    def handle_received_chain(self, chain_data: List[Dict[str, Any]]):
        """
        Obsługuje otrzymany łańcuch. Implementuje prostą zasadę "najdłuższy łańcuch wygrywa".
        """
        if len(chain_data) <= len(self.blockchain.chain):
            # print(f"[Node:{self.port}] Otrzymany łańcuch nie jest dłuższy. Ignorowanie.")
            return
            
        print(f"[Node:{self.port}] Otrzymano dłuższy łańcuch. Weryfikacja...")
        
        # Tworzymy tymczasowy, testowy łańcuch
        temp_blockchain = Blockchain()
        temp_blockchain.chain = [] # Usuwamy genesis block
        
        try:
            for i, block_data in enumerate(chain_data):
                block = Block.from_dict(block_data)
                
                if i == 0:
                    # Weryfikacja Genesis Block
                    if block.index != 0 or block.previous_hash != "0":
                        raise ValueError("Invalid Genesis Block")
                    temp_blockchain.chain.append(block)
                else:
                    # Weryfikacja kolejnych bloków
                    if not temp_blockchain.add_block(block):
                        raise ValueError(f"Niepoprawny blok #{block.index} w otrzymanym łańcuchu.")
            
            # Jeśli cały łańcuch jest poprawny, zastępujemy nasz
            self.blockchain = temp_blockchain
            print(f"[Node:{self.port}] Zamieniono lokalny łańcuch na nowy, poprawny. Długość: {len(self.blockchain.chain)}")
            
        except Exception as e:
            print(f"[Node:{self.port}] Otrzymany łańcuch jest niepoprawny: {e}. Ignorowanie.")


    async def run(self):
        await self.start_server()
        await asyncio.sleep(0.5) # Daj serwerowi chwilę na start
        await self.connect_to_peers()
        
        if self.is_miner:
            # Uruchom pętlę górnika jako zadanie w tle
            asyncio.create_task(self.miner_loop())
            
        ## NOWOŚĆ: Uruchomienie API Flaska w osobnym wątku
        # Użyjemy portu o 1000 wyższego niż port P2P (np. 8765 -> 9765)
        api_port = self.port + 1000
        
        api_thread = Thread(
            target=run_flask_app, 
            args=(self.flask_app, api_port), 
            daemon=True  # Ustawienie na True sprawi, że wątek zamknie się wraz z programem
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
            miner_flag_index = sys.argv.index("--miner")
            miner_address = sys.argv[miner_flag_index + 1]
            is_miner = True
            peers_start_index = miner_flag_index + 2
            print(f"Startuję jako GÓRNIK. Adres na nagrody: {miner_address}")
        except IndexError:
            print("Błąd: flaga --miner musi być zakończona adresem.")
            sys.exit(1)
            
    peers = sys.argv[peers_start_index:]

    node = Node(port=port, peers=peers, is_miner=is_miner, miner_address=miner_address)

    await node.run()

    print(f"[Node:{port}] Uruchomiony. Znani peerzy: {peers}")
    await asyncio.Future()  # Trzymaj program przy życiu


if __name__ == "__main__":
    asyncio.run(main())