import os
import json
from utils import load_key_from_file, text_to_int, int_to_text
from crypto.rsa import encrypt as rsa_encrypt, decrypt as rsa_decrypt
import base64
from crypto.signature import sign as rsa_sign, verify as rsa_verify
from crypto.sha256 import sha256


USERS_FILE = 'storage/users.json'
KEYS_DIR = 'storage/keys'
OUTPUT_DIR = 'storage/messages'

def _ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def _load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def _get_public_key(username):
    users = _load_users()
    if username not in users:
        raise ValueError(f"User '{username}' not found")
    pub = users[username]['public_key']
    return int(pub['e']), int(pub['n'])

def _get_private_key(username):
    key_path = f"{KEYS_DIR}/{username}.priv"
    priv = load_key_from_file(key_path)
    return {'d': int(priv['d']), 'n': int(priv['n'])}

def _load_plaintext(infile=None, text=None):
    if text is not None:
        return text.encode('utf-8')
    elif infile:
        infile_path = infile if os.path.isabs(infile) else os.path.join(OUTPUT_DIR, infile)
        with open(infile_path, 'rb') as f:
            return f.read()
    else:
        raise ValueError("No plaintext input provided")

def _encrypt_with_pubkey(pub_key, plaintext: bytes) -> str:
    message_int = int.from_bytes(plaintext, byteorder='big')
    ciphertext_int = rsa_encrypt(message_int, pub_key)
    return hex(ciphertext_int)

def _save_ciphertext(ciphertext_hex, output_path):
    _ensure_output_dir()
    if output_path is None:
        print("[+] Ciphertext (hex):")
        print(ciphertext_hex)
        return

    full_path = output_path if os.path.isabs(output_path) else os.path.join(OUTPUT_DIR, output_path)
    with open(full_path, 'w') as f:
        f.write(ciphertext_hex)
    print(f"[+] Ciphertext saved to '{full_path}'")
    print("[+] Ciphertext (hex):")
    print(ciphertext_hex)

def encrypt_message(to_username, input_data, output_path, algorithm, is_text=False):
    if algorithm != 'rsa':
        raise NotImplementedError(f"Algorithm '{algorithm}' not supported yet.")
    
    pub_key = _get_public_key(to_username)
    plaintext = _load_plaintext(text=input_data if is_text else None,
                                infile=input_data if not is_text else None)
    ciphertext_hex = _encrypt_with_pubkey(pub_key, plaintext)
    _save_ciphertext(ciphertext_hex, output_path)

def encrypt_message_with_pubkey(pubkey_path, infile, text, output_path, algorithm):
    if algorithm != 'rsa':
        raise NotImplementedError(f"Algorithm '{algorithm}' not supported for direct public key encryption yet.")

    with open(pubkey_path, 'r') as f:
        pubkey_data = json.load(f)
    pub_key = (int(pubkey_data['e']), int(pubkey_data['n']))

    plaintext = _load_plaintext(text=text, infile=infile)
    ciphertext_hex = _encrypt_with_pubkey(pub_key, plaintext)
    _save_ciphertext(ciphertext_hex, output_path)

def encrypt_message_with_pubkey_direct(e, n, infile, text, output_path, algorithm):
    if algorithm != 'rsa':
        raise NotImplementedError(f"Algorithm '{algorithm}' not supported for direct public key encryption yet.")

    pub_key = (e, n)
    plaintext = _load_plaintext(text=text, infile=infile)
    ciphertext_hex = _encrypt_with_pubkey(pub_key, plaintext)
    _save_ciphertext(ciphertext_hex, output_path)

def decrypt_message(username, infile=None, cipher_hex_or_b64=None, outfile=None):
    priv_key = _get_private_key(username)

    if infile:
        infile_path = infile if os.path.isabs(infile) else os.path.join(OUTPUT_DIR, infile)
        with open(infile_path, 'r') as f:
            ciphertext_str = f.read().strip()
    elif cipher_hex_or_b64:
        ciphertext_str = cipher_hex_or_b64.strip()
    else:
        raise ValueError("No ciphertext input provided")

    try:
        decoded_bytes = base64.b64decode(ciphertext_str, validate=True)
        ciphertext_int = int.from_bytes(decoded_bytes, byteorder='big')
    except (base64.binascii.Error, ValueError):
        ciphertext_int = int(ciphertext_str, 16) if ciphertext_str.startswith("0x") else int(ciphertext_str)

    plaintext_int = rsa_decrypt(ciphertext_int, (priv_key['d'], priv_key['n']))
    plaintext = int_to_text(plaintext_int)

    if outfile:
        _ensure_output_dir()
        outfile_path = outfile if os.path.isabs(outfile) else os.path.join(OUTPUT_DIR, outfile)
        with open(outfile_path, 'w', encoding='utf-8') as f:
            f.write(plaintext)
        print(f"[+] Message decrypted and saved to '{outfile_path}'")

    print("[+] Decrypted plaintext:")
    print(plaintext)

def sign_message(username, infile, outfile, algorithm, text=None):
    if algorithm != 'rsa':
        raise NotImplementedError(f"Algorithm '{algorithm}' not supported for signing yet.")

    priv_key = _get_private_key(username)

    if text is not None:
        message = text
    else:
        input_path = infile if os.path.isabs(infile) else os.path.join(OUTPUT_DIR, infile)
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            message = f.read()

    signature = rsa_sign(message, (priv_key['d'], priv_key['n']))

    if outfile:
        _ensure_output_dir()
        output_path = outfile if os.path.isabs(outfile) else os.path.join(OUTPUT_DIR, outfile)
        with open(output_path, 'w') as f:
            f.write(str(signature))
        print(f"[+] Signature saved to '{output_path}'")

    print("[+] Signature (int):")
    print(signature)




def verify_signature(username, infile=None, sigfile=None, sig_str=None, algorithm='rsa', text=None):
    if algorithm != 'rsa':
        raise NotImplementedError(f"Algorithm '{algorithm}' not supported for verification yet.")

    pub_key = _get_public_key(username)

    if text is not None:
        message = text
    else:
        input_path = infile if os.path.isabs(infile) else os.path.join(OUTPUT_DIR, infile)
        with open(input_path, 'r', encoding='utf-8') as f:
            message = f.read()

    # Load signature either from sigfile or from sig_str
    if sigfile is not None:
        sig_path = sigfile if os.path.isabs(sigfile) else os.path.join(OUTPUT_DIR, sigfile)
        with open(sig_path, 'r') as f:
            signature = int(f.read().strip())
    elif sig_str is not None:
        try:
            signature = int(sig_str.strip())
        except Exception:
            raise ValueError("Signature string must be an integer.")
    else:
        raise ValueError("No signature provided for verification.")

    is_valid = rsa_verify(message, signature, pub_key)

    print("[+] Signature is VALID" if is_valid else "[!] Signature is INVALID")


