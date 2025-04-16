import customtkinter as ctk
from bitcoinlib.keys import Key, HDKey
from bitcoinlib.wallets import Wallet, WalletError, wallet_delete_if_exists
from bitcoinlib.services.services import Service
import time

# Customtkinter setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class BitcoinWalletApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Bitcoin Wallet Key Info")
        self.geometry("600x500")
        self.resizable(True, True)
        self.minsize(400, 300)

        # Wallet name with timestamp to avoid conflicts
        self.wallet_name = f"mywallet_{int(time.time())}"

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Frame for private key input
        key_frame = ctk.CTkFrame(self)
        key_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(key_frame, text="Enter Private Key (hex):").pack(side="left", padx=5)
        self.key_entry = ctk.CTkEntry(key_frame, width=400, placeholder_text="e.g., 0000000000000000000000000000000000000000000000000fc07a1825367bbe")
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

        # Configure tags for colored text
        self.result_text.tag_config("green", foreground="green")
        self.result_text.tag_config("red", foreground="red")

    def copy_results(self):
        """Copy the contents of the result text area to the clipboard."""
        content = self.result_text.get("0.0", "end").strip()
        if content and content != "Results will appear here...":
            self.clipboard_clear()
            self.clipboard_append(content)
            self.result_text.insert("end", "\nResults copied to clipboard!\n")
        else:
            self.result_text.insert("end", "\nNo results to copy.\n")

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

        # Step 1: Create key objects for compressed and uncompressed keys
        try:
            key_compressed = Key(private_key_hex, compressed=True)
            key_uncompressed = Key(private_key_hex, compressed=False)
            wif_compressed = key_compressed.wif()
            wif_uncompressed = key_uncompressed.wif()

            self.result_text.insert("end", "Private Key Details:\n")
            self.result_text.insert("end", f"  Hex: {private_key_hex}\n")
            self.result_text.insert("end", f"  WIF Compressed: {wif_compressed}\n")
            self.result_text.insert("end", f"  WIF Uncompressed: {wif_uncompressed}\n")
            self.result_text.insert("end", f"  Public Key (Compressed): {key_compressed.public_hex}\n")
            self.result_text.insert("end", f"  Public Key (Uncompressed): {key_uncompressed.public_hex}\n")
            self.result_text.insert("end", f"  Legacy Address (Compressed): {key_compressed.address()}\n")
            self.result_text.insert("end", f"  Legacy Address (Uncompressed): {key_uncompressed.address()}\n\n")
        except Exception as e:
            self.result_text.insert("end", f"Error creating key: {e}\n")
            return

        # Step 2: Delete the wallet if it exists
        try:
            wallet_delete_if_exists(self.wallet_name)
            self.result_text.insert("end", f"Deleted existing wallet '{self.wallet_name}' (if it existed).\n")
        except Exception as e:
            self.result_text.insert("end", f"Error deleting wallet: {e}\n")

        # Step 3: Create a new wallet with the compressed private key and get xpriv
        wallet = None
        xpriv = None
        try:
            wallet = Wallet.create(self.wallet_name, keys=wif_compressed, network='bitcoin', witness_type='legacy')
            self.result_text.insert("end", f"Created new wallet '{self.wallet_name}' (compressed key).\n")
            # Try to get xpriv from wallet's main key
            xpriv = wallet.main_key.wif
            if not xpriv.startswith('xprv'):
                # Fallback: Generate xpriv using HDKey
                hd_key = HDKey(private_key_hex, network='bitcoin')
                xpriv = hd_key.extended_key()
            self.result_text.insert("end", f"BIP32 Extended Private Key (xpriv):\n  {xpriv}\n\n")
        except Exception as e:
            self.result_text.insert("end", f"Error creating wallet or generating xpriv: {str(e)}\n")
            # Fallback: Try generating xpriv without wallet
            try:
                hd_key = HDKey(private_key_hex, network='bitcoin')
                xpriv = hd_key.extended_key()
                self.result_text.insert("end", f"BIP32 Extended Private Key (xpriv, fallback):\n  {xpriv}\n\n")
            except Exception as fallback_e:
                self.result_text.insert("end", f"Error generating xpriv (fallback): {fallback_e}\n")

        # Step 4: Update the wallet's transaction history and balance (compressed key)
        if wallet:
            try:
                wallet.scan()
                self.result_text.insert("end", f"Scanned wallet for transactions (compressed key).\n")
            except Exception as e:
                self.result_text.insert("end", f"Error scanning wallet: {e}\n")

            # Step 5: Fetch and display the wallet balance with color
            try:
                balance = wallet.balance()
                balance_btc = balance / 100000000
                self.result_text.insert("end", "Wallet Info (Compressed Key):\n")
                self.result_text.insert("end", f"  Wallet Name: {self.wallet_name}\n")
                if balance > 0:
                    self.result_text.insert("end", f"  Balance: {balance_btc} BTC\n", "green")
                else:
                    self.result_text.insert("end", f"  Balance: {balance_btc} BTC\n", "red")
            except Exception as e:
                self.result_text.insert("end", f"Error fetching wallet balance: {e}\n")

        # Step 6: Use a service provider to verify balances for both addresses with color
        try:
            service = Service(network='bitcoin')
            # Compressed address balance
            address_compressed = key_compressed.address()
            balance_compressed = service.getbalance(address_compressed)
            balance_compressed_btc = balance_compressed / 100000000
            self.result_text.insert("end", "\nDirect Balance Check:\n")
            self.result_text.insert("end", f"  Compressed Address: {address_compressed}\n")
            if balance_compressed > 0:
                self.result_text.insert("end", f"  Balance: {balance_compressed_btc} BTC\n", "green")
            else:
                self.result_text.insert("end", f"  Balance: {balance_compressed_btc} BTC\n", "red")
            # Uncompressed address balance
            address_uncompressed = key_uncompressed.address()
            balance_uncompressed = service.getbalance(address_uncompressed)
            balance_uncompressed_btc = balance_uncompressed / 100000000
            self.result_text.insert("end", f"  Uncompressed Address: {address_uncompressed}\n")
            if balance_uncompressed > 0:
                self.result_text.insert("end", f"  Balance: {balance_uncompressed_btc} BTC\n", "green")
            else:
                self.result_text.insert("end", f"  Balance: {balance_uncompressed_btc} BTC\n", "red")
        except Exception as e:
            self.result_text.insert("end", f"Error fetching balance directly: {e}\n")

        # Enable the copy button after results are generated
        self.copy_button.configure(state="normal")

if __name__ == "__main__":
    app = BitcoinWalletApp()
    app.mainloop()