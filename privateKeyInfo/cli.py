import argparse
from bitcoinlib.keys import Key, HDKey
from bitcoinlib.wallets import Wallet, wallet_delete_if_exists
from bitcoinlib.services.services import Service
import time
from termcolor import colored

def validate_private_key(private_key_hex):
    """Validate the private key format."""
    if not private_key_hex:
        return False, "Error: Private key cannot be empty."
    if len(private_key_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in private_key_hex):
        return False, "Error: Private key must be a 64-character hexadecimal string."
    return True, ""

def process_key(private_key_hex):
    """Process the private key and return formatted results."""
    results = []

    # Validate private key
    is_valid, error = validate_private_key(private_key_hex)
    if not is_valid:
        return [error]

    # Step 1: Create key objects for compressed and uncompressed keys
    try:
        key_compressed = Key(private_key_hex, compressed=True)
        key_uncompressed = Key(private_key_hex, compressed=False)
        wif_compressed = key_compressed.wif()
        wif_uncompressed = key_uncompressed.wif()

        results.append("Private Key Details:")
        results.append(f"  Hex: {private_key_hex}")
        results.append(f"  WIF Compressed: {wif_compressed}")
        results.append(f"  WIF Uncompressed: {wif_uncompressed}")
        results.append(f"  Public Key (Compressed): {key_compressed.public_hex}")
        results.append(f"  Public Key (Uncompressed): {key_uncompressed.public_hex}")
        results.append(f"  Legacy Address (Compressed): {key_compressed.address()}")
        results.append(f"  Legacy Address (Uncompressed): {key_uncompressed.address()}")
        results.append("")
    except Exception as e:
        return [f"Error creating key: {e}"]

    # Step 2: Generate BIP32 extended private key (xpriv)
    try:
        hd_key = HDKey(private_key_hex, network='bitcoin')
        xpriv = hd_key.extended_key()
        results.append(f"BIP32 Extended Private Key (xpriv):")
        results.append(f"  {xpriv}")
        results.append("")
    except Exception as e:
        results.append(f"Error generating xpriv: {e}")
        results.append("")

    # Step 3: Create a wallet for balance checking
    wallet_name = f"mywallet_{int(time.time())}"
    try:
        wallet_delete_if_exists(wallet_name)
        results.append(f"Deleted existing wallet '{wallet_name}' (if it existed).")
    except Exception as e:
        results.append(f"Error deleting wallet: {e}")

    wallet = None
    try:
        wallet = Wallet.create(wallet_name, keys=wif_compressed, network='bitcoin', witness_type='legacy')
        results.append(f"Created new wallet '{wallet_name}' (compressed key).")
    except Exception as e:
        results.append(f"Error creating wallet: {str(e)}")

    # Step 4: Update wallet's transaction history and balance
    if wallet:
        try:
            wallet.scan()
            results.append(f"Scanned wallet for transactions (compressed key).")
        except Exception as e:
            results.append(f"Error scanning wallet: {e}")

        try:
            balance = wallet.balance()
            balance_btc = balance / 100000000
            results.append("Wallet Info (Compressed Key):")
            results.append(f"  Wallet Name: {wallet_name}")
            balance_text = f"  Balance: {balance_btc} BTC"
            if balance > 0:
                results.append(colored(balance_text, "green"))
            else:
                results.append(colored(balance_text, "red"))
            results.append("")
        except Exception as e:
            results.append(f"Error fetching wallet balance: {e}")
            results.append("")

    # Step 5: Direct balance check using service provider
    try:
        service = Service(network='bitcoin')
        address_compressed = key_compressed.address()
        balance_compressed = service.getbalance(address_compressed)
        balance_compressed_btc = balance_compressed / 100000000
        results.append("Direct Balance Check:")
        results.append(f"  Compressed Address: {address_compressed}")
        balance_comp_text = f"  Balance: {balance_compressed_btc} BTC"
        if balance_compressed > 0:
            results.append(colored(balance_comp_text, "green"))
        else:
            results.append(colored(balance_comp_text, "red"))

        address_uncompressed = key_uncompressed.address()
        balance_uncompressed = service.getbalance(address_uncompressed)
        balance_uncompressed_btc = balance_uncompressed / 100000000
        results.append(f"  Uncompressed Address: {address_uncompressed}")
        balance_uncomp_text = f"  Balance: {balance_uncompressed_btc} BTC"
        if balance_uncompressed > 0:
            results.append(colored(balance_uncomp_text, "green"))
        else:
            results.append(colored(balance_uncomp_text, "red"))
    except Exception as e:
        results.append(f"Error fetching balance directly: {e}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Bitcoin Wallet CLI: Display key details and balance for a private key.")
    parser.add_argument("--key", help="Private key in hex format (64 characters).")
    args = parser.parse_args()

    # Get private key from argument or prompt
    if args.key:
        private_key_hex = args.key.strip()
    else:
        private_key_hex = input("Enter Private Key (hex, 64 characters): ").strip()

    # Process the key and print results
    results = process_key(private_key_hex)
    for line in results:
        print(line)

if __name__ == "__main__":
    main()