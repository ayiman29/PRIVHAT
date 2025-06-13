
# cli.py
import argparse
from user_manager import create_user
from crypto_engine import encrypt_message, decrypt_message, sign_message, verify_signature

def main():
    parser = argparse.ArgumentParser(prog='privhat', description='Cryptography CLI Tool')

    subparsers = parser.add_subparsers(dest='command')

    # Create user
    parser_create = subparsers.add_parser('create-user')
    parser_create.add_argument('username')
    parser_create.add_argument('--alg', choices=['rsa', 'ecc', 'elgamal'], required=True)

    # Encrypt
    parser_encrypt = subparsers.add_parser('encrypt')
    parser_encrypt.add_argument('--to', required=True)
    parser_encrypt.add_argument('--in', dest='infile', required=True)
    parser_encrypt.add_argument('--out', required=True)
    parser_encrypt.add_argument('--alg', choices=['rsa', 'ecc', 'elgamal', 'hybrid'], required=True)

    # Decrypt
    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--user', required=True)
    parser_decrypt.add_argument('--in', dest='infile', required=True)
    parser_decrypt.add_argument('--out', required=True)

    # Sign
    parser_sign = subparsers.add_parser('sign')
    parser_sign.add_argument('--user', required=True)
    parser_sign.add_argument('--in', dest='infile', required=True)
    parser_sign.add_argument('--out', required=True)
    parser_sign.add_argument('--alg', choices=['rsa', 'ecdsa'], required=True)

    # Verify
    parser_verify = subparsers.add_parser('verify')
    parser_verify.add_argument('--from', dest='username', required=True)
    parser_verify.add_argument('--in', dest='infile', required=True)
    parser_verify.add_argument('--sig', required=True)
    parser_verify.add_argument('--alg', choices=['rsa', 'ecdsa'], required=True)

    args = parser.parse_args()

    if args.command == 'create-user':
        create_user(args.username, args.alg)

    elif args.command == 'encrypt':
        encrypt_message(args.to, args.infile, args.out, args.alg)

    elif args.command == 'decrypt':
        decrypt_message(args.user, args.infile, args.out)

    elif args.command == 'sign':
        sign_message(args.user, args.infile, args.out, args.alg)

    elif args.command == 'verify':
        verify_signature(args.username, args.infile, args.sig, args.alg)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
