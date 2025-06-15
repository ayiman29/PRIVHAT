import os
import json
import argparse
from colorama import Fore, Style, init
from user_manager import create_user, import_public_key, delete_user
from crypto_engine import (
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    encrypt_message_with_pubkey,
    encrypt_message_with_pubkey_direct
)

def ensure_storage():
    os.makedirs('storage/keys', exist_ok=True)
    os.makedirs('storage/messages', exist_ok=True)
    users_file = 'storage/users.json'
    if not os.path.exists(users_file):
        with open(users_file, 'w') as f:
            json.dump({}, f)

def print_banner():
    init(autoreset=True)
    banner = r'''
    ____  ____  _____    __   __  _____  ______
   / __ \/ __ \/  _/ |  / /  / / / /   |/_  __/
  / /_/ / /_/ // / | | / /  / /_/ / /| | / /   
 / ____/ _, _// /  | |/ /  / __  / ___ |/ /    
/_/   /_/ |_/___/  |___/  /_/ /_/_/  |_/_/     

'''
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.YELLOW + "           Made by ayiman29\n" + Style.RESET_ALL)

def main():
    ensure_storage()
    print_banner()

    parser = argparse.ArgumentParser(prog='PRIVHAT', description='Cryptography CLI Tool')
    subparsers = parser.add_subparsers(dest='command')

    # Create user
    parser_create = subparsers.add_parser('create-user')
    parser_create.add_argument('username')
    parser_create.add_argument('--alg', choices=['rsa', 'ecc', 'elgamal'], required=True)

    # Delete user
    parser_delete = subparsers.add_parser('delete-user')
    parser_delete.add_argument('username', help='Username to delete')

    # Import public key
    parser_import = subparsers.add_parser('import-pubkey')
    parser_import.add_argument('username')
    parser_import.add_argument('--e', type=int, required=True, help='Public exponent')
    parser_import.add_argument('--n', type=int, required=True, help='Public modulus')

    # List user
    parser_list = subparsers.add_parser('list-users', help='List all users and their key status')

    # Encrypt
    parser_encrypt = subparsers.add_parser('encrypt')
    group_target = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_target.add_argument('--to', help='Username of recipient')
    group_target.add_argument('--pubkey-file', help='Path to public key JSON file')
    group_target.add_argument('--pubkey-e', type=int, help='Public key exponent (e)')
    parser_encrypt.add_argument('--pubkey-n', type=int, help='Public key modulus (n), required if --pubkey-e is used')

    group_encrypt_input = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_encrypt_input.add_argument('--in', dest='infile', help="Input file containing plaintext")
    group_encrypt_input.add_argument('--text', help="Plaintext message directly as argument")

    parser_encrypt.add_argument('--out', help='Output file to save ciphertext (optional). If omitted, prints to stdout.')
    parser_encrypt.add_argument('--alg', choices=['rsa', 'ecc', 'elgamal', 'hybrid'], required=True)

    # Decrypt
    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--user', required=True, help='Username to load private key')
    group_decrypt_input = parser_decrypt.add_mutually_exclusive_group(required=True)
    group_decrypt_input.add_argument('--in', dest='infile', help='File containing ciphertext (hex)')
    group_decrypt_input.add_argument('--cipher', help='Ciphertext as hex string')
    parser_decrypt.add_argument('--out', help='Output file to save plaintext (optional)')

    # Sign
    parser_sign = subparsers.add_parser('sign')
    parser_sign.add_argument('--user', required=True)

    group_sign_input = parser_sign.add_mutually_exclusive_group(required=True)
    group_sign_input.add_argument('--in', dest='infile', help='Input file to sign')
    group_sign_input.add_argument('--text', help='Plaintext message to sign directly')

    parser_sign.add_argument('--out', help='(Optional) Output file to save signature')
    parser_sign.add_argument('--alg', choices=['rsa', 'ecdsa'], required=True)


    # Verify
    parser_verify = subparsers.add_parser('verify')
    parser_verify.add_argument('--from', dest='username', required=True)

    group_input = parser_verify.add_mutually_exclusive_group(required=True)
    group_input.add_argument('--in', dest='infile', help='Input file containing message')
    group_input.add_argument('--text', help='Plain text message to verify signature against')

    group_sig_input = parser_verify.add_mutually_exclusive_group(required=True)
    group_sig_input.add_argument('--sig', help='Signature file path')
    group_sig_input.add_argument('--cipher', help='Signature string directly')

    parser_verify.add_argument('--alg', choices=['rsa', 'ecdsa'], required=True)


    args = parser.parse_args()
    if args.command == 'encrypt':
        if args.pubkey_e and not args.pubkey_n:
            parser.error("--pubkey-n is required when --pubkey-e is used")

    if args.command == 'create-user':
        create_user(args.username, args.alg)

    elif args.command == 'delete-user':
        delete_user(args.username)

    elif args.command == 'import-pubkey':
        import_public_key(args.username, args.e, args.n)

    elif args.command == 'list-users':
        from user_manager import list_users
        list_users()

    elif args.command == 'encrypt':
        if args.pubkey_e and args.pubkey_n:
            if args.infile:
                encrypt_message_with_pubkey_direct(args.pubkey_e, args.pubkey_n, args.infile, None, args.out, args.alg)
            else:
                encrypt_message_with_pubkey_direct(args.pubkey_e, args.pubkey_n, None, args.text, args.out, args.alg)

        elif args.pubkey_file:
            if args.infile:
                encrypt_message_with_pubkey(args.pubkey_file, args.infile, None, args.out, args.alg)
            else:
                encrypt_message_with_pubkey(args.pubkey_file, None, args.text, args.out, args.alg)

        else:
            if args.infile:
                encrypt_message(args.to, args.infile, args.out, args.alg, is_text=False)
            else:
                encrypt_message(args.to, args.text, args.out, args.alg, is_text=True)

    elif args.command == 'decrypt':
        decrypt_message(args.user, args.infile, args.cipher, args.out)

    elif args.command == 'sign':
        sign_message(args.user, args.infile, args.out, args.alg, text=args.text)

    elif args.command == 'verify':
        verify_signature(username=args.username, infile=args.infile, sigfile=args.sig, sig_str=args.cipher, algorithm=args.alg, text=args.text)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
