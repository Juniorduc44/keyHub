
import customtkinter as ctk
import hashlib
import base58
from bitcoinlib.wallets import Wallet, WalletError
import bitcoinlib.wallets
from bitcoinlib.keys import Key
from bitcoinlib.services.services import Service

# Customtkinter setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def hex_to_wif_uncompressed(private_key_hex):
    """
    Convert a hex private key to WIF format (uncompressed).
    
    Args:
        private_key_hex (str): The private key in hex format (64 characters).
    
    Returns:
        str: The uncompressed WIF private key.
    """
    # Validate the private key
    if len(private_key_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in private_key_hex):
        raise ValueError("Private key must be a 64-character hexadecimal string.")

    # Add the Bitcoin mainnet prefix (0x80)
    extended_key = "80" + private_key_hex

    # Compute the checksum (double SHA256, take first 4 bytes)
    first_sha = hashlib.sha256(bytes.fromhex(extended_key)).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha.hex()[:8]

    # Combine extended key and checksum
    key_with_checksum = extended_key + checksum

    # Encode with Base58
    wif_private_key = base58.b58encode(bytes.fromhex(key_with_checksum)).decode('utf-8')
    return wif_private_key

class BitcoinWalletApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Bitcoin Wallet Key Info")
        self.geometry("600x500")
        self.resizable(True, True)
        self.minsize(400, 300)

        # Wallet name
        self.wallet_name = "mywallet_00"

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Frame for private key input
        key_frame = ctk.CTkFrame(self)
        key_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(key_frame, text="Enter Private Key (hex):").pack(side="left", padx=5)
        self.key_entry = ctk.CTkEntry(key_frame, width=400, placeholder_text="e.g., e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262")
        self.key_entry.pack(side="left", padx=5)

        # Button to process the key
        self.process_button = ctk.CTkButton(self, text="Process Key", command=self.process_key)
        self.process_button.pack(pady=10)

        # Button to copy results
        self.copy_button = ctk.CTkButton(self, text="Copy Results", command=self.copy_results, state="disabled")
        self.copy_button.pack(pady=5)

        # Text area to display results
        self.result_text = ctk.CTkTextbox(self, width=550, height=300, wrap="word")
        self.result_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.result_text.insert("0.0", "Results will appear here...\n")

    def copy_results(self):
        """Copy the contents of the result text area to the clipboard."""
        content = self.result_text.get("0.0", "end").strip()
        if content and content != "Results will appear here...":
            self.clipboard_clear()
            self.clipboard_append(content)
            ctk.CTkMessageBox.show_info(self, "Success", "Results copied to clipboard!")
        else:
            ctk.CTkMessageBox.show_warning(self, "Warning", "No results to copy.")

    def process_key(self):
        """Process the private key and display wallet information."""
        # Clear previous results
        self.result_text.delete("0.0", "end")
        self.copy_button.configure(state="disabled")

        # Get the private key from the entry
        private_key_hex = self.key_entry.get().strip()

        # Validate the private key
        if not private_key_hex:
            self.result_text.insert("end", "Error: Please enter a private key.\n")
            return
        if len(private_key_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in private_key_hex):
            self.result_text.insert("end", "Error: Private key must be a 64-character hexadecimal string.\n")
            return

        # Step 1: Create key objects for both compressed and uncompressed keys
        try:
            # Compressed key (default in bitcoinlib)
            key_compressed = Key(private_key_hex, compressed=True)
            # Uncompressed key
            key_uncompressed = Key(private_key_hex, compressed=False)
            # Generate the uncompressed WIF using the manual method
            wif_uncompressed = hex_to_wif_uncompressed(private_key_hex)

            self.result_text.insert("end", "Complete Key and Address Details:\n")
            self.result_text.insert("end", "-" * 50 + "\n")
            self.result_text.insert("end", f"Private Key (hex):\n{private_key_hex}\n")
            self.result_text.insert("end", f"Private Key WIF (Compressed):\n{key_compressed.wif()}\n")
            self.result_text.insert("end", f"Private Key WIF (Uncompressed):\n{wif_uncompressed}\n\n")
            self.result_text.insert("end", f"Public Key (Compressed):\n{key_compressed.public_hex}\n")
            self.result_text.insert("end", f"Public Key (Uncompressed):\n{key_uncompressed.public_hex}\n\n")
            self.result_text.insert("end", f"Legacy Address (Compressed):\n{key_compressed.address()}\n")
            self.result_text.insert("end", f"Legacy Address (Uncompressed):\n{key_uncompressed.address()}\n\n")
        except Exception as e:
            self.result_text.insert("end", f"Error creating key: {e}\n")
            return

        # Step 2: Delete the wallet if it exists
        try:
            bitcoinlib.wallets.wallet_delete_if_exists(self.wallet_name)
            self.result_text.insert("end", f"Deleted existing wallet '{self.wallet_name}' (if it existed).\n")
        except WalletError as e:
            if "does not exist" in str(e).lower():
                pass  # Wallet didn't exist, no issue
            else:
                self.result_text.insert("end", f"Error deleting wallet: {e}\n")
        except Exception as e:
            self.result_text.insert("end", f"Unexpected error during wallet deletion: {e}\n")

        # Step 3: Create a new wallet with the compressed private key
        try:
            wallet = Wallet.create(self.wallet_name, keys=key_compressed.wif(), network='bitcoin')
            self.result_text.insert("end", f"\nCreated new wallet '{self.wallet_name}' (compressed key).\n")
        except Exception as e:
            self.result_text.insert("end", f"Error creating wallet: {e}\n")
            return

        # Step 4: Update the wallet's transaction history and balance (compressed key)
        try:
            wallet.scan()  # Scan the blockchain for transactions
            self.result_text.insert("end", f"Scanned wallet for transactions (compressed key).\n")
        except Exception as e:
            self.result_text.insert("end", f"Error scanning wallet: {e}\n")

        # Step 5: Fetch and display the balance (compressed key)
        try:
            balance = wallet.balance()
            self.result_text.insert("end", f"\nWallet Info (Compressed Key):\n")
            self.result_text.insert("end", f"Wallet Name: {self.wallet_name}\n")
            self.result_text.insert("end", f"Balance: {balance} BTC\n")
        except Exception as e:
            self.result_text.insert("end", f"Error fetching balance: {e}\n")

        # Step 6: Use a service provider to verify the balance for both addresses
        try:
            service = Service(network='bitcoin')
            # Compressed address balance
            address_compressed = key_compressed.address()
            balance_compressed = service.getbalance(address_compressed)
            self.result_text.insert("end", f"\nDirect Balance Check (via service provider):\n")
            self.result_text.insert("end", f"\nCompressed Address: {address_compressed}\n")
            self.result_text.insert("end", f"Balance (Compressed): {balance_compressed / 100000000} BTC\n")
            # Uncompressed address balance
            address_uncompressed = key_uncompressed.address()
            balance_uncompressed = service.getbalance(address_uncompressed)
            self.result_text.insert("end", f"Uncompressed Address: {address_uncompressed}\n")
            self.result_text.insert("end", f"Balance (Uncompressed): {balance_uncompressed / 100000000} BTC\n")
        except Exception as e:
            self.result_text.insert("end", f"Error fetching balance directly: {e}\n")

        # Enable the copy button after results are generated
        self.copy_button.configure(state="normal")

if __name__ == "__main__":
    app = BitcoinWalletApp()
    app.mainloop()