import json
import time
import hashlib
from typing import List, Dict, Any, Optional

from penercoin_hd import HDWallet

class Transaction:
    """
    Reprezentuje pojedynczą transakcję.
    Zakładamy, że 'tx_data' zawiera {'from', 'to', 'amount', 'timestamp'}
    'sender_pubkey' to nieskompresowany klucz publiczny (64 bajty hex)
    """
    def __init__(self, tx_data: Dict[str, Any], signature: str, sender_pubkey: str):
        self.tx_data = tx_data
        self.signature = signature
        self.sender_pubkey = sender_pubkey
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Oblicza hash danych transakcji, który jest podpisywany."""
        # spójna serializacja - json dumps
        tx_string = json.dumps(self.tx_data, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def is_valid(self) -> bool:
        """
        Weryfikuje podpis transakcji.
        """
        tx_hash_bytes = bytes.fromhex(self.tx_hash)
        
        
        # Weryfikacja podpisu - musi pochodzić z sender_pubkey - nie robimy sprawdzania środków jeszcze, bo naszym zdaniem to element 3 etapu, czyli transakcji
        return HDWallet.verify(self.sender_pubkey, tx_hash_bytes, self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_data": self.tx_data,
            "signature": self.signature,
            "sender_pubkey": self.sender_pubkey
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        return cls(data['tx_data'], data['signature'], data['sender_pubkey'])


class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Transaction], previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce # uproszczony nonce dla PoW
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Oblicza hash całego bloku."""
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        # Używamy sort_keys dla spójnego hashowania
        block_string = json.dumps(block_content, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        block = cls(
            index=data['index'],
            timestamp=data['timestamp'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            nonce=data['nonce']
        )
        block.hash = data['hash'] # Ustawiamy hash, który przyszedł z sieci
        return block


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []
        # Uproszczony Proof-of-Work: hash musi zaczynać się od '00'
        self.difficulty = 2 


    def create_genesis_block(self) -> Block:
        """Tworzy pierwszy blok łańcucha."""
        # timestamp 0, eby genesis block był taki sam w kaźdym węźle
        return Block(index=0, timestamp=0, transactions=[], previous_hash="0")

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_transaction(self, transaction: Transaction) -> bool:
        """
        Dodaje nową transakcję do puli oczekujących, jeśli jest valid
        """
        if not transaction.is_valid():
            print("[Blockchain] Invalid transaction signature.")
            return False
        
        self.pending_transactions.append(transaction)
        print(f"[Blockchain] Transaction added to mempool. Pending: {len(self.pending_transactions)}")
        return True

    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        """
        Tworzy nowy blok (kopie) ze wszystkich oczekujących transakcji.
        W nagrodę dodaje transakcję "coinbase" dla górnika.
        """
        if not self.pending_transactions:
            print("[Blockchain] No transactions to mine.")
            return None

        #przekazanie adresu zamiast nagrody
        print(f"[Blockchain] Mining block for {miner_address}...")

        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            transactions=self.pending_transactions,
            previous_hash=latest_block.hash
        )

        # prosty PoW
        new_block.hash = self.proof_of_work(new_block)
        
        print(f"[Blockchain] Block Mined! Hash: {new_block.hash}")
        self.chain.append(new_block)
        
        # Wyczyszczenie puli oczekujących transakcji
        self.pending_transactions = []
        
        return new_block

    def proof_of_work(self, block: Block) -> str:
        """
        Prosty algorytm Proof-of-Work.
        Znajduje hash, który zaczyna się od 'self.difficulty' zer.
        """
        block.nonce = 0
        computed_hash = block.calculate_hash()
        prefix = '0' * self.difficulty
        
        while not computed_hash.startswith(prefix):
            block.nonce += 1
            computed_hash = block.calculate_hash()
            
        return computed_hash

    def add_block(self, new_block: Block) -> bool:
        """
        Dodaje nowy blok otrzymany z sieci, jeśli jest ważny.
        To jest "Weryfikacja bloków pobieranych od innych węzłów".
        """
        latest_block = self.get_latest_block()
        prefix = '0' * self.difficulty # definiujemy liczbę zer na początku hasha do weryfikacji

        # sprawdzenie inedksu
        if new_block.index != latest_block.index + 1:
            print("[Blockchain] Invalid block index.")
            return False
            
        # sprawdzenie previous hash
        if new_block.previous_hash != latest_block.hash:
            print("[Blockchain] Invalid previous hash.")
            return False

        # PoW
        # sprawdzamy czy hash bloku jest poprawny i czy spełnia warunek trudności - liczba zer
        if new_block.hash != new_block.calculate_hash() or not new_block.hash.startswith(prefix):
            print("[Blockchain] Invalid block hash or PoW.")
            return False
            
        # Weryfikacja wszystkich transakcji w bloku
        for tx in new_block.transactions:
            if not tx.is_valid():
                print(f"[Blockchain] Block contains an invalid transaction: {tx.tx_hash}")
                return False

        #jak sie zgadza to akceptujemy blok do chaina
        self.chain.append(new_block)
        
        # usuwamy transakcje z tego bloku z puli oczekujacych transakcji
        self.pending_transactions = [
            p_tx for p_tx in self.pending_transactions
            if p_tx.tx_hash not in [tx.tx_hash for tx in new_block.transactions]
        ]
        
        print(f"[Blockchain] New block #{new_block.index} accepted from network.")
        return True

    def is_chain_valid(self) -> bool:
        """Sprawdza integralność całego łańcucha."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Sprawdzenie hasha bloku
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {i} hash is invalid.")
                return False
                
            # Sprawdzenie powiązania
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} previous_hash is invalid.")
                return False
                
            # Sprawdzenie PoW
            if not current_block.hash.startswith('0' * self.difficulty):
                print(f"Block {i} PoW is invalid.")
                return False
        
        return True