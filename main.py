import struct
import hashlib

class CompactSizeEncoder:
    """
    Encodes an integer into Bitcoin's CompactSize format.
    This format is used to indicate the length of following data.

    Encoding rules:
    - If value < 0xFD (253), it is encoded as a single byte.
    - If value <= 0xFFFF (65535), it is encoded as 0xFD followed by the 2-byte little-endian value.
    - If value <= 0xFFFFFFFF (4294967295), it is encoded as 0xFE followed by the 4-byte little-endian value.
    - If value > 0xFFFFFFFF, it is encoded as 0xFF followed by the 8-byte little-endian value.
    """
    def encode(self, value: int) -> bytes:
        """
        Encodes a given integer value into CompactSize bytes.

        Args:
            value (int): The integer to encode.

        Returns:
            bytes: The CompactSize byte representation.

        Raises:
            ValueError: If the value is negative or exceeds u64 max.
        """
        if not isinstance(value, int) or value < 0 or value > 18446744073709551615:
            raise ValueError(f"Value must be a non-negative integer within u64 range (0 to 18446744073709551615), got {value}")

        if value < 0xFD:
            return value.to_bytes(1, byteorder='little')
        elif value <= 0xFFFF:
            return b'\xfd' + value.to_bytes(2, byteorder='little')
        elif value <= 0xFFFFFFFF:
            return b'\xfe' + value.to_bytes(4, byteorder='little')
        else:
            return b'\xff' + value.to_bytes(8, byteorder='little')


class CompactSizeDecoder:
    """
    Decodes Bitcoin's CompactSize bytes into an integer.
    """
    def decode(self, data: bytes) -> tuple[int, int]:
        """
        Decodes a CompactSize integer from the beginning of a byte sequence.

        Args:
            data (bytes): The byte sequence to decode from.

        Returns:
            tuple[int, int]: A tuple containing the decoded integer value
                             and the number of bytes consumed.

        Raises:
            ValueError: If data is too short or has an invalid prefix.
        """
        if not data:
            raise ValueError("Data is too short to decode CompactSize.")

        first_byte = data[0]

        if first_byte < 0xFD:
            return (first_byte, 1)
        elif first_byte == 0xFD:
            if len(data) < 3:
                raise ValueError("Data too short for 0xFD prefix: need 3 bytes.")
            value = int.from_bytes(data[1:3], byteorder='little')
            return (value, 3)
        elif first_byte == 0xFE:
            if len(data) < 5:
                raise ValueError("Data too short for 0xFE prefix: need 5 bytes.")
            value = int.from_bytes(data[1:5], byteorder='little')
            return (value, 5)
        else:  # 0xFF
            if len(data) < 9:
                raise ValueError("Data too short for 0xFF prefix: need 9 bytes.")
            value = int.from_bytes(data[1:9], byteorder='little')
            return (value, 9)


class TransactionData:
    """
    A class to represent and manage simplified Bitcoin transaction data.
    Illustrates lists, dictionaries, tuples, unpacking, and various loop constructs.
    """
    def __init__(self, version: int = 1, lock_time: int = 0):
        self.version = version
        self.inputs = []   # List of dictionaries, each representing a transaction input
        self.outputs = []  # List of tuples, each representing a transaction output
        self.lock_time = lock_time
        self.metadata = {}  # Dictionary for arbitrary transaction metadata

    def add_input(self, tx_id: str, vout_index: int, script_sig: str, sequence: int = 0xFFFFFFFF):
        """
        Adds a new transaction input using list.append() and a dictionary.
        """
        input_data = {
            "prev_txid": tx_id,
            "prev_vout": vout_index,
            "script_sig": script_sig,
            "sequence": sequence,
        }
        self.inputs.append(input_data)
        print(f"Input added: txid={tx_id}, vout={vout_index}")

    def add_output(self, value_satoshi: int, script_pubkey: str):
        """
        Adds a new transaction output using list.append() and a tuple.
        """
        output_data = (value_satoshi, script_pubkey)
        self.outputs.append(output_data)
        print(f"Output added: value={value_satoshi} satoshis, script={script_pubkey}")

    def get_input_details(self) -> list[dict]:
        """
        Retrieves details of all transaction inputs.
        Demonstrates 'for' loop and 'enumerate'.
        """
        detailed_inputs = []
        print("\n--- Input Details (using for and enumerate) ---")
        for index, input_data in enumerate(self.inputs):
            print(f"  Input #{index}:")
            prev_txid = input_data.get("prev_txid")
            prev_vout = input_data.get("prev_vout")
            script_sig = input_data.get("script_sig")
            print(f"    prev_txid : {prev_txid}")
            print(f"    prev_vout : {prev_vout}")
            print(f"    script_sig: {script_sig}")
            detailed_inputs.append(input_data.copy())
        return detailed_inputs

    def summarize_outputs(self, min_value: int = 0) -> tuple[int, int]:
        """
        Summarizes transaction outputs, skipping or breaking based on conditions.
        Demonstrates 'while', 'continue', and 'break' loops.
        """
        SATOSHI_THRESHOLD = 1_000_000_000  # 10 BTC in satoshis

        total_satoshi = 0
        valid_outputs_count = 0
        index = 0
        print("\n--- Summarizing Outputs (using while, continue, break) ---")

        while index < len(self.outputs):
            value, script = self.outputs[index]
            index += 1

            if not isinstance(value, int) or value < 0:
                print(f"  Skipping output with invalid value: {value}")
                continue

            if value < min_value:
                print(f"  Skipping output below min_value ({value} < {min_value})")
                continue

            total_satoshi += value
            valid_outputs_count += 1
            print(f"  Including output: value={value} satoshis, script={script}")

            if total_satoshi > SATOSHI_THRESHOLD:
                print(f"  Total satoshis exceeded 1 Billion. Breaking summarization.")
                break

        return (total_satoshi, valid_outputs_count)

    def update_metadata(self, new_data: dict):
        """
        Updates the transaction metadata using dictionary methods.
        """
        self.metadata.update(new_data)
        print(f"Updated metadata: {self.metadata}")

    def get_metadata_value(self, key: str, default=None):
        """
        Retrieves a value from metadata using dict.get().
        """
        return self.metadata.get(key, default)

    def get_transaction_header(self) -> tuple:
        """
        Returns core transaction header elements as a tuple.
        """
        return (self.version, len(self.inputs), len(self.outputs), self.lock_time)

    def set_transaction_header(self, version: int, num_inputs: int, num_outputs: int, lock_time: int):
        """
        Sets transaction header elements using multiple assignment.
        """
        # Unpack directly using multiple assignment as requested by the exercise/comments
        self.version, _, _, self.lock_time = version, num_inputs, num_outputs, lock_time
        
        # Explicitly truncate/resize inputs and outputs lists based on the passed counts
        self.inputs = self.inputs[:num_inputs]
        self.outputs = self.outputs[:num_outputs]
        
        print(f"Set header via multiple assignment: version={self.version}, lock_time={self.lock_time}")


class UTXOSet:
    """
    Manages a set of Unspent Transaction Outputs (UTXOs).
    Illustrates Python's `set` data structure and its methods.

    UTXOs are represented as tuples: (transaction_id_hex, vout_index, amount_satoshi).
    """
    def __init__(self):
        self.utxos = set()

    def add_utxo(self, tx_id: str, vout_index: int, amount: int):
        """Adds a UTXO to the set."""
        utxo = (tx_id, vout_index, amount)
        self.utxos.add(utxo)
        print(f"UTXO added: ({tx_id}, {vout_index}, {amount})")

    def remove_utxo(self, tx_id: str, vout_index: int, amount: int) -> bool:
        """Removes a UTXO from the set if it exists."""
        utxo = (tx_id, vout_index, amount)
        if utxo in self.utxos:
            self.utxos.discard(utxo)
            print(f"Removed UTXO: ({tx_id}, {vout_index}, {amount})")
            return True
        print(f"UTXO not found: {utxo}")
        return False

    def get_balance(self) -> int:
        """Calculates the total balance from all UTXOs in the set."""
        return sum(amount for _, _, amount in self.utxos)

    def find_sufficient_utxos(self, target_amount: int) -> set:
        """
        Finds a subset of UTXOs that sum up to at least the target amount.
        """
        selected = set()
        running_total = 0
        for utxo in sorted(self.utxos, key=lambda x: x[2], reverse=True):
            if running_total >= target_amount:
                break
            selected.add(utxo)
            running_total += utxo[2]
        if running_total >= target_amount:
            print(f"Found sufficient UTXOs totaling {running_total} satoshis for target {target_amount}.")
            return selected
        print(f"Could not find sufficient UTXOs: only {running_total} of {target_amount} satoshis available.")
        return set()

    def get_total_utxo_count(self) -> int:
        """Returns the number of UTXOs in the set."""
        return len(self.utxos)

    def is_subset_of(self, other_utxo_set: 'UTXOSet') -> bool:
        """Checks if this UTXO set is a subset of another."""
        return self.utxos.issubset(other_utxo_set.utxos)

    def combine_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        """Combines two UTXO sets into a new one."""
        combined_set = UTXOSet()
        combined_set.utxos = self.utxos.union(other_utxo_set.utxos)
        return combined_set

    def find_common_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        """Finds UTXOs common to two sets using set.intersection()."""
        common_set = UTXOSet()
        common_set.utxos = self.utxos.intersection(other_utxo_set.utxos)
        return common_set


def generate_block_headers(
    prev_block_hash: str,
    merkle_root: str,
    timestamp: int,
    bits: int,
    start_nonce: int = 0,
    max_attempts: int = 1000
):
    """
    A generator function that simulates generating block headers by incrementing the nonce.
    """
    print(f"\n--- Generating Block Headers (using generator) ---")
    nonce = start_nonce
    attempts = 0

    while attempts < max_attempts:
        header_data = {
            "version": 1,
            "prev_block_hash": prev_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce,
        }

        header_str = str(header_data).encode('utf-8')
        simulated_hash = hashlib.sha256(header_str).hexdigest()

        print(f"  Attempt {attempts + 1}: nonce={nonce}, hash prefix={simulated_hash[:16]}...")

        yield header_data

        nonce += 1
        attempts += 1

        if attempts % 100 == 0 and attempts < max_attempts:
            print(f"  ... {attempts} attempts made ...")