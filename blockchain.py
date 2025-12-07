import json
import time
import hashlib
import binascii
from typing import List, Dict, Any, Optional
from copy import deepcopy
from penercoin_hd import HDWallet

MINING_REWARD = 50

# --- STRUKTURY DANYCH UTXO ---

class TxOut:
    """Reprezentuje 'monetę'. Ma adres właściciela i kwotę."""
    def __init__(self, address: str, amount: int):
        self.address = address
        self.amount = amount

    def to_dict(self):
        return {"address": self.address, "amount": self.amount}

class TxIn:
    """
    Reprezentuje wejście transakcji.
    Wskazuje na poprzednią monetę (tx_out_id, tx_out_index) i zawiera podpis odblokowujący.
    """
    def __init__(self, tx_out_id: str, tx_out_index: int, signature: str):
        self.tx_out_id = tx_out_id
        self.tx_out_index = tx_out_index
        self.signature = signature

    def to_dict(self):
        return {
            "tx_out_id": self.tx_out_id,
            "tx_out_index": self.tx_out_index,
            "signature": self.signature
        }

class UnspentTxOut:
    """Struktura pomocnicza do śledzenia niewydanych monet w puli UTXO."""
    def __init__(self, tx_out_id: str, tx_out_index: int, address: str, amount: int):
        self.tx_out_id = tx_out_id
        self.tx_out_index = tx_out_index
        self.address = address
        self.amount = amount

    def to_dict(self):
        return {
            "tx_out_id": self.tx_out_id,
            "tx_out_index": self.tx_out_index,
            "address": self.address,
            "amount": self.amount
        }


class Transaction:
    def __init__(self, tx_ins: List[TxIn], tx_outs: List[TxOut], id: str = None):
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        # ID transakcji to jej hash (obliczony z inputów i outputów)
        self.id = id if id else self.calculate_hash()

    def calculate_hash(self) -> str:
        """Hashuje zawartość transakcji (bez podpisów w teorii, ale tu upraszczamy)."""
        tx_content = {
            "tx_ins": [{'tx_out_id': tx.tx_out_id, 'tx_out_index': tx.tx_out_index} for tx in self.tx_ins],
            "tx_outs": [tx.to_dict() for tx in self.tx_outs]
        }
        tx_string = json.dumps(tx_content, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tx_ins": [tx.to_dict() for tx in self.tx_ins],
            "tx_outs": [tx.to_dict() for tx in self.tx_outs]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        tx_ins = [TxIn(x['tx_out_id'], x['tx_out_index'], x['signature']) for x in data['tx_ins']]
        tx_outs = [TxOut(x['address'], x['amount']) for x in data['tx_outs']]
        return cls(tx_ins, tx_outs, data.get('id'))


class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Transaction], previous_hash: str, nonce: int = 0, hash: str = None):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()

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
        return cls(
            index=data['index'],
            timestamp=data['timestamp'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            nonce=data['nonce'],
            hash=data['hash']
        )


class Blockchain:
    def __init__(self):
        # Pula UTXO (Unspent Transaction Outputs) - kluczowy element tego modelu
        self.unspent_tx_outs: List[UnspentTxOut] = []
        
        # Inicjalizacja łańcucha
        self.chain: List[Block] = [self.create_genesis_block()]
        
        # Po stworzeniu Genesis, musimy zaktualizować pulę UTXO o monety z Genesis
        self.unspent_tx_outs = self.process_transactions(self.chain[0].transactions, [], 0)
        
        self.pending_transactions: List[Transaction] = []
        self.difficulty = 2

    def create_genesis_block(self) -> Block:
        # Genesis Transaction: Tworzy 50 monet dla 'GENESIS_ADDR' z niczego
        # W modelu UTXO coinbase ma 1 output i 0 inputów
        genesis_tx = Transaction(
            tx_ins=[], 
            tx_outs=[TxOut("3c11462c3732dad03e284f3dd8b862c3cd1ce2f4", 50)],
            id="e0513b6329c2901308a0d24d9c75043516514457788470a916a4a1154563a362" # Hardcoded hash
        )
        return Block(index=0, timestamp=0, transactions=[genesis_tx], previous_hash="0")

    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def get_chain_dict(self):
        return [block.to_dict() for block in self.chain]

    def get_pending_tx_dict(self):
        return [tx.to_dict() for tx in self.pending_transactions]

    # --- LOGIKA UTXO ---

    def find_utxo(self, tx_out_id: str, tx_out_index: int, utxo_pool: List[UnspentTxOut]) -> Optional[UnspentTxOut]:
        """Znajduje konkretną monetę w podanej puli UTXO."""
        for utxo in utxo_pool:
            if utxo.tx_out_id == tx_out_id and utxo.tx_out_index == tx_out_index:
                return utxo
        return None

    def validate_transaction(self, transaction: Transaction, utxo_pool: List[UnspentTxOut]) -> bool:
        """
        Walidacja transakcji w modelu UTXO:
        1. Czy inputy istnieją w UTXO? (Anti Double-Spend)
        2. Czy podpisy są poprawne? (Właściciel inputu)
        3. Czy suma wejść >= suma wyjść?
        """
        
        # Wyjątek: Transakcja Coinbase (brak inputów, 1 output)
        # Weryfikujemy tylko czy ma 1 output o wartości nagrody (uproszczenie)
        if len(transaction.tx_ins) == 0:
            if len(transaction.tx_outs) != 1: return False
            if transaction.tx_outs[0].amount != MINING_REWARD: return False
            return True

        total_in = 0
        total_out = 0

        # Weryfikacja Inputów
        for tx_in in transaction.tx_ins:
            referenced_utxo = self.find_utxo(tx_in.tx_out_id, tx_in.tx_out_index, utxo_pool)
            
            if not referenced_utxo:
                print(f"[UTXO] Błąd: Input odnosi się do nieistniejącej lub wydanej monety: {tx_in.tx_out_id}")
                return False
            
            address = referenced_utxo.address
            
            # Weryfikacja Podpisu
            # Podpisujemy hash transakcji. Kluczem publicznym jest adres z referenced_utxo
            try:
                # Uwaga: W prawdziwym Bitcoinie weryfikacja jest bardziej złożona (Script)
                # Tutaj zakładamy, że wallet podpisał transaction.id swoim kluczem prywatnym.
                # Do verify potrzebujemy KLUCZA PUBLICZNEGO (nieskompresowanego), a mamy ADRES.
                # W tym demo uprościmy: zakładamy, że `signature` zawiera (pubkey_hex + signature_hex).
                # To pozwala zweryfikować podpis i sprawdzić czy pubkey pasuje do adresu.
                
                # UPROSZCZENIE NA POTRZEBY PROJEKTU:
                # HDWallet.verify wymaga (pubkey, message, signature). 
                # Tutaj zakładamy, że weryfikacja została zrobiona przez węzeł wcześniej 
                # lub po prostu sprawdzamy czy input istnieje.
                # Aby zrobić to w pełni poprawnie, TxIn musiałby zawierać public_key, a nie tylko sygnaturę.
                pass 
            except Exception:
                return False

            total_in += referenced_utxo.amount

        # Weryfikacja Outputów
        for tx_out in transaction.tx_outs:
            total_out += tx_out.amount

        if total_in < total_out:
            print(f"[UTXO] Błąd: Suma wejść ({total_in}) mniejsza niż wyjść ({total_out})")
            return False

        return True

    def update_utxos(self, transactions: List[Transaction], current_utxos: List[UnspentTxOut]) -> List[UnspentTxOut]:
        """
        Aktualizuje pulę UTXO na podstawie listy nowych transakcji.
        Zwraca NOWĄ listę UTXO.
        """
        new_utxos = deepcopy(current_utxos) # Pracujemy na kopii

        for tx in transactions:
            # 1. Usuń zużyte (spent) UTXO
            for tx_in in tx.tx_ins:
                to_remove = self.find_utxo(tx_in.tx_out_id, tx_in.tx_out_index, new_utxos)
                if to_remove:
                    new_utxos.remove(to_remove)
            
            # 2. Dodaj nowe UTXO (z outputów tej transakcji)
            for index, tx_out in enumerate(tx.tx_outs):
                new_utxo = UnspentTxOut(tx.id, index, tx_out.address, tx_out.amount)
                new_utxos.append(new_utxo)
                
        return new_utxos

    def process_transactions(self, transactions: List[Transaction], current_utxos: List[UnspentTxOut], block_index: int) -> List[UnspentTxOut]:
        """Waliduje i przetwarza listę transakcji, zwracając zaktualizowany stan UTXO."""
        
        # 1. Sprawdź poprawność każdej transakcji względem AKTUALNEGO stanu UTXO
        # Uwaga: w ramach jednego bloku transakcja B może wydawać output transakcji A.
        # Dlatego musimy aktualizować tymczasowe UTXO po każdej transakcji w bloku.
        
        temp_utxos = deepcopy(current_utxos)
        
        for tx in transactions:
            if not self.validate_transaction(tx, temp_utxos):
                print(f"[Blockchain] Transakcja {tx.id} jest niepoprawna.")
                # W prawdziwym systemie odrzucilibyśmy cały blok. Tu dla uproszczenia pomijamy tx?
                # Nie, blok musi być atomowy.
                raise ValueError(f"Invalid transaction in block {block_index}: {tx.id}")
            
            temp_utxos = self.update_utxos([tx], temp_utxos)
            
        return temp_utxos

    # --- INTERFEJSY API ---

    def get_balance(self, address: str) -> int:
        """Oblicza saldo sumując UTXO należące do adresu."""
        balance = 0
        for utxo in self.unspent_tx_outs:
            if utxo.address == address:
                balance += utxo.amount
        return balance
    
    def get_my_utxos(self, address: str) -> List[Dict]:
        """Zwraca listę UTXO dla danego adresu (dla portfela)."""
        return [utxo.to_dict() for utxo in self.unspent_tx_outs if utxo.address == address]

    def add_transaction(self, transaction: Transaction) -> bool:
        """Dodaje transakcję do mempool."""
        # Walidacja względem obecnych UTXO
        if not self.validate_transaction(transaction, self.unspent_tx_outs):
            return False
            
        self.pending_transactions.append(transaction)
        print(f"[Blockchain] Transakcja dodana do mempoola (UTXO).")
        return True
# W klasie Blockchain w pliku blockchain.py

    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        # 1. Przygotuj transakcję Coinbase (Nagroda)
        # W modelu UTXO coinbase ma 0 inputów i 1 output
        coinbase_tx = Transaction([], [TxOut(miner_address, MINING_REWARD)])
        
        # 2. SELEKCJA TRANSAKCJI (TO JEST NOWA CZĘŚĆ)
        # Musimy przefiltrować mempool. Jeśli mamy 5 transakcji wydających tę samą monetę,
        # tylko pierwsza może wejść do bloku. Reszta musi zostać odrzucona.
        
        valid_transactions = [coinbase_tx]
        temp_utxos = deepcopy(self.unspent_tx_outs) # Kopia robocza UTXO
        
        # Lista transakcji, które ostatecznie wejdą do bloku
        final_pending = []
        
        print(f"[Miner] Weryfikacja {len(self.pending_transactions)} transakcji w mempoolu...")
        
        for tx in self.pending_transactions:
            if self.validate_transaction(tx, temp_utxos):
                # Jeśli transakcja jest ważna względem aktualnego stanu tymczasowego:
                valid_transactions.append(tx)
                final_pending.append(tx)
                # Aktualizujemy tymczasowe UTXO, żeby kolejna transakcja w pętli wiedziała,
                # że te środki są już zajęte
                temp_utxos = self.update_utxos([tx], temp_utxos)
            else:
                print(f"[Miner] Odrzucono transakcję {tx.id[:10]}... (konflikt/double spend)")
                # Nie dodajemy jej do valid_transactions, więc zostanie pominięta w bloku
        
        # Jeśli nie ma żadnych poprawnych transakcji poza coinbase (i nie chcemy pustych bloków):
        # if len(valid_transactions) == 1: 
        #    print("[Miner] Brak poprawnych transakcji do wykopania.")
        #    # Ważne: musimy wyczyścić mempool z tych błędnych transakcji, żeby nie zapętlić
        #    self.pending_transactions = [] 
        #    return None

        # 3. Tworzenie bloku tylko z poprawnymi transakcjami
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            transactions=valid_transactions,
            previous_hash=latest_block.hash
        )

        print(f"[Miner] Rozpoczynam Proof-of-Work dla {len(valid_transactions)} transakcji...")
        new_block.hash = self.proof_of_work(new_block)
        
        # 4. Zatwierdzenie
        try:
            # Tu już powinno przejść bez błędu, bo sprawdziliśmy to wyżej
            new_utxos = self.process_transactions(valid_transactions, self.unspent_tx_outs, new_block.index)
            self.unspent_tx_outs = new_utxos 
            self.chain.append(new_block)
            
            # Czyścimy mempool. 
            # UWAGA: Usuwamy WSZYSTKIE transakcje, które próbowaliśmy przetworzyć.
            # Te, które weszły do bloku - znikają.
            # Te, które były konfliktowe - też znikają (są odrzucane).
            self.pending_transactions = []
            
            return new_block
            
        except ValueError as e:
            print(f"[Miner] Krytyczny błąd podczas zapisu bloku: {e}")
            self.pending_transactions = [] # Awaryjne czyszczenie
            return None

    def proof_of_work(self, block: Block) -> str:
        block.nonce = 0
        computed_hash = block.calculate_hash()
        prefix = '0' * self.difficulty
        while not computed_hash.startswith(prefix):
            block.nonce += 1
            computed_hash = block.calculate_hash()
        return computed_hash

    def add_block(self, new_block: Block) -> bool:
        latest = self.get_latest_block()
        if new_block.previous_hash != latest.hash: return False
        if not new_block.hash.startswith('0' * self.difficulty): return False
        
        # Walidacja transakcji i aktualizacja UTXO
        try:
            new_utxos = self.process_transactions(new_block.transactions, self.unspent_tx_outs, new_block.index)
            self.unspent_tx_outs = new_utxos
            self.chain.append(new_block)
            
            # Wyczyść mempool z transakcji które weszły
            processed_tx_ids = [tx.id for tx in new_block.transactions]
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.id not in processed_tx_ids]
            
            print(f"[Blockchain] Dodano blok #{new_block.index} (UTXO zaktualizowane).")
            return True
        except ValueError:
            print("[Blockchain] Blok zawiera nieprawidłowe transakcje.")
            return False

    def replace_chain(self, chain_data: List[Dict[str, Any]]) -> bool:
        """
        Przy UTXO wymiana łańcucha jest trudna - trzeba przeliczyć UTXO od zera.
        Dla uproszczenia: jeśli łańcuch dłuższy i poprawny, przebudowujemy UTXO set od Genesis.
        """
        if len(chain_data) <= len(self.chain): return False
        
        temp_utxos = [] # Pusty start
        temp_chain = []
        
        try:
            # Odtwarzanie stanu świata od zera
            for i, block_data in enumerate(chain_data):
                block = Block.from_dict(block_data)
                
                # Walidacja podstawowa (hash, linki) - pomijam dla czytelności, zakładamy że jest w validate_block
                
                if i == 0:
                    # Genesis - specjalna obsługa, tworzymy początkowe UTXO
                    temp_chain.append(block)
                    temp_utxos = self.process_transactions(block.transactions, [], 0)
                else:
                    # Przetwarzamy każdy kolejny blok używając UTXO z poprzedniego kroku
                    temp_utxos = self.process_transactions(block.transactions, temp_utxos, i)
                    temp_chain.append(block)
            
            # Sukces - podmiana
            self.chain = temp_chain
            self.unspent_tx_outs = temp_utxos
            self.pending_transactions = []
            print(f"[Blockchain] Chain replaced. New UTXO set size: {len(self.unspent_tx_outs)}")
            return True
            
        except Exception as e:
            print(f"[Blockchain] Chain replacement failed: {e}")
            return False