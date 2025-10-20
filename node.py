import asyncio
import websockets
import json
import sys


class Node:
    def __init__(self, port: int, peers=None):
        self.port = port
        self.peers = peers or []
        self.server = None
        self.connections = set()
        self.known_peers = set(self.peers)
        self.on_transaction = None

    async def start_server(self):
        async def handler(ws):  
            self.connections.add(ws)
            try:
                async for msg in ws:
                    await self.handle_message(ws, msg)
            except websockets.ConnectionClosed:
                pass
            finally:
                self.connections.remove(ws)

        self.server = await websockets.serve(handler, "localhost", self.port)
        print(f"[Node] Server listening on ws://localhost:{self.port}")

    async def connect_to_peers(self):
        for p in list(self.peers):
            try:
                ws = await websockets.connect(p)
                self.connections.add(ws)
                asyncio.create_task(self.receive_loop(ws))
                print(f"[Node:{self.port}] Connected to peer {p}")
            except Exception as e:
                print(f"[Node:{self.port}] Could not connect to {p}: {e}")

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
            print("[Node] Invalid JSON")
            return

        t = msg.get("type")
        data = msg.get("data")

        if t == "PING":
            await ws.send(json.dumps({"type": "PONG"}))
        elif t == "TRANSACTION":
            print(f"[Node:{self.port}] TRANSACTION received: {data}")
            if self.on_transaction:
                await self.on_transaction(data)
            await self.broadcast(raw_msg, exclude=ws)
        elif t == "PONG":
            pass
        else:
            print(f"[Node] Unknown message type: {t}")

    async def broadcast(self, message: str, exclude=None):
        for conn in list(self.connections):
            if conn is exclude:
                continue
            try:
                await conn.send(message)
            except Exception:
                pass

    async def run(self):
        await self.start_server()
        await asyncio.sleep(0.5)
        await self.connect_to_peers()


async def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    port = int(sys.argv[1])
    peers = sys.argv[2:]

    node = Node(port=port, peers=peers)

    async def on_tx(data):
        print(f"[Node:{port}] Transaction received from network: {data}")

    node.on_transaction = on_tx

    await node.run()

    print(f"[Node:{port}] Running. Known peers: {peers}")
    await asyncio.Future() 


if __name__ == "__main__":
    asyncio.run(main())


