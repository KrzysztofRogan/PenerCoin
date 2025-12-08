import json
import time
import hashlib
from typing import List, Dict, Any, Optional
from penercoin_hd import HDWallet

GENESIS_ADDRESS = "3c11462c3732dad03e284f3dd8b862c3cd1ce2f4"
PREMINE_AMOUNT = 1000000  
MINING_REWARD = 50        

class Transaction:
    def __init__(self, tx_data: Dict[str, Any], signature: str, sender_pubkey: str):
        self.tx_data = tx_data
        self.signature = signature
        self.sender_pubkey = sender_pubkey
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        tx_string = json.dumps(self.tx_data, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def is_valid(self) -> bool:
        sender = self.tx_data.get("from")
        amount = self.tx_data.get("amount")
        
        if sender == "COINBASE":
            if amount != MINING_REWARD:
                return False
            if self.sender_pubkey != "":
                return False
            if self.signature != "":
                return False
            
        if amount < 0 or type(amount) is not int:
            return False
            
            
        if not self.signature or not self.sender_pubkey:
            return False
            
        tx_hash_bytes = bytes.fromhex(self.tx_hash)
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
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
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
        block.hash = data['hash']
        return block


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []
        self.difficulty = 3

    def create_genesis_block(self) -> Block:
        genesis_tx_data = {
            "from": "COINBASE",
            "to": GENESIS_ADDRESS,
            "amount": PREMINE_AMOUNT,
            "timestamp": 0
        }
        

        genesis_tx = Transaction(genesis_tx_data, signature="", sender_pubkey="")
        

        return Block(index=0, timestamp=0, transactions=[genesis_tx], previous_hash="0")

    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def get_chain_dict(self) -> List[Dict[str, Any]]:
        return [block.to_dict() for block in self.chain]

    def get_pending_tx_dict(self) -> List[Dict[str, Any]]:
        return [tx.to_dict() for tx in self.pending_transactions]

    def get_balance(self, address: str, up_to_index: int = None) -> int:
        balance = 0
        limit = up_to_index if up_to_index is not None else len(self.chain)
        for i in range(limit):
            block = self.chain[i]
            for tx in block.transactions:
                if tx.tx_data.get('to') == address:
                    balance += tx.tx_data['amount']
                if tx.tx_data.get('from') == address:
                    balance -= tx.tx_data['amount']
        return balance
    
    def get_nonce(self, address: str) -> int:
        count = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_data.get('from') == address:
                    count += 1

        for tx in self.pending_transactions:
            if tx.tx_data.get('from') == address:
                count += 1
                
        return count
    
    def get_confirmed_nonce(self, address: str, up_to_index: int = None) -> int:
        count = 0
        limit = up_to_index if up_to_index is not None else len(self.chain)
        for i in range(limit):
            block = self.chain[i]
            for tx in block.transactions:
                if tx.tx_data.get('from') == address:
                    count += 1
        return count
    
    def add_transaction(self, transaction: Transaction) -> bool:
        sender = transaction.tx_data.get('from')
        amount = transaction.tx_data.get('amount')
        tx_nonce = transaction.tx_data.get('nonce')

        if sender == "COINBASE": return False


        if transaction.tx_hash in [t.tx_hash for t in self.pending_transactions]:
            return False 
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_hash == transaction.tx_hash:
                    return False

        if not transaction.is_valid():
            print(f"[Mempool Error] Błąd walidacji transakcji")
            return False
            
        expected_nonce = self.get_nonce(sender)
        if tx_nonce != expected_nonce:
            print(f"[Mempool Error] Błąd Nonce dla {sender}: Jest {tx_nonce}, oczekiwano {expected_nonce}")
            return False

        current_balance = self.get_balance(sender)
        pending_spend = sum(t.tx_data['amount'] for t in self.pending_transactions if t.tx_data['from'] == sender)
        
        if current_balance < (amount + pending_spend):
            print(f"[Mempool Error] Brak środków. Ma: {current_balance}, Pending: {pending_spend}, Chce: {amount}")
            return False
        
        self.pending_transactions.append(transaction)
        print(f"[Mempool] Transakcja dodana (Nonce: {tx_nonce}). Oczekujących: {len(self.pending_transactions)}")
        return True

    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        coinbase_tx_data = {
            "from": "COINBASE",
            "to": miner_address,
            "amount": MINING_REWARD,
            "timestamp": time.time()
        }
        coinbase_tx = Transaction(coinbase_tx_data, signature="", sender_pubkey="")
        
        block_transactions = [coinbase_tx] + self.pending_transactions

        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            transactions=block_transactions,
            previous_hash=latest_block.hash
        )

        new_block.hash = self.proof_of_work(new_block)
        
        self.chain.append(new_block)
        self.pending_transactions = [] 
        
        return new_block

    def proof_of_work(self, block: Block) -> str:
        block.nonce = 0
        computed_hash = block.calculate_hash()
        prefix = '0' * self.difficulty
        
        while not computed_hash.startswith(prefix):
            block.nonce += 1
            computed_hash = block.calculate_hash()
            
        return computed_hash
    
    # sprawdzamy kazda transakcje w dodawanym bloku
    def verify_block_transactions(self, block: Block) -> bool:
        temp_balance_changes = {}
        temp_nonce_tracker = {}

        if not block.transactions: return False
        if block.transactions[0].tx_data.get("from") != "COINBASE": return False
        
        for i, tx in enumerate(block.transactions):
            sender = tx.tx_data.get("from")
            amount = tx.tx_data.get("amount")
            
            if sender == "COINBASE":
                if i != 0: return False
                continue

            tx_nonce = tx.tx_data.get("nonce")
            if tx_nonce is None: return False


            confirmed_nonce = self.get_confirmed_nonce(sender, up_to_index=block.index)
            nonce_offset = temp_nonce_tracker.get(sender, 0)
            
            expected = confirmed_nonce + nonce_offset
            
            if tx_nonce != expected:
                print(f"Block valid error: Bad nonce for {sender}. Got {tx_nonce}, expected {expected}")
                return False
            
            temp_nonce_tracker[sender] = nonce_offset + 1

            if not tx.is_valid(): return False

            current_balance = self.get_balance(sender, up_to_index=block.index)
            balance_change = temp_balance_changes.get(sender, 0)
            
            if (current_balance + balance_change) < amount:
                return False

            temp_balance_changes[sender] = balance_change - amount
            recipient = tx.tx_data.get("to")
            temp_balance_changes[recipient] = temp_balance_changes.get(recipient, 0) + amount

        return True

    def add_block(self, new_block: Block) -> bool:
        latest_block = self.get_latest_block()
        prefix = '0' * self.difficulty

        if new_block.index != latest_block.index + 1: return False
        if new_block.previous_hash != latest_block.hash: return False
        if not new_block.hash.startswith(prefix): return False
        if new_block.hash != new_block.calculate_hash(): return False

        if not self.verify_block_transactions(new_block):
            print("[Blockchain] Blok odrzucony: błąd weryfikacji transakcji (nonce/saldo)")
            return False

        self.chain.append(new_block)
        
        # Czyszczenie mempoola
        processed_hashes = [tx.tx_hash for tx in new_block.transactions]
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.tx_hash not in processed_hashes]
        
        print(f"[Blockchain] Zaakceptowano blok #{new_block.index}")
        return True

    def replace_chain(self, chain_data: List[Dict[str, Any]]) -> bool:
        if len(chain_data) <= len(self.chain): return False
        
        print(f"[Blockchain] Weryfikacja dłuższego łańcucha...")
        temp_chain = []
        
        try:
            for i, block_data in enumerate(chain_data):
                block = Block.from_dict(block_data)
                
                if i == 0:
                    our_genesis = self.create_genesis_block()
                    if block.calculate_hash() != our_genesis.calculate_hash():
                        raise ValueError("Invalid Genesis Block hash")
                    temp_chain.append(block)
                    continue

                prev_block = temp_chain[-1]
                if block.previous_hash != prev_block.hash:
                    raise ValueError(f"Invalid link at block {i}")
                if not block.hash.startswith('0' * self.difficulty):
                    raise ValueError(f"Invalid PoW at block {i}")
                # walidacja podpisow transakcji
                for tx in block.transactions:
                    if not tx.is_valid():
                        raise ValueError(f"Invalid tx in block {i}")
                            
                temp_chain.append(block)
            
            self.chain = temp_chain
            self.pending_transactions = [] 
            print(f"[Blockchain] Zastąpiono łańcuch. Nowa długość: {len(self.chain)}")
            return True
            
        except Exception as e:
            print(f"[Blockchain] Odrzucono łańcuch: {e}")
            return False

    def is_chain_valid(self) -> bool:
        real_genesis = self.create_genesis_block()
        if self.chain[0].calculate_hash() != real_genesis.calculate_hash():
            return False

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current.hash != current.calculate_hash(): return False
            if current.previous_hash != prev.hash: return False
        return True
    
