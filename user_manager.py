import os
import json
from crypto.rsa import generate_keypair
from utils import save_key_to_file

USERS_FILE = 'storage/users.json'
KEYS_DIR = 'storage/keys'

def _ensure_storage():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)

def _load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def _save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def create_user(username, alg):
    _ensure_storage()
    users = _load_users()

    if username in users:
        print(f"[!] User '{username}' already exists.")
        return

    if alg == 'rsa':
        public_key, private_key = generate_keypair(512)

        pub_dict = {'e': public_key[0], 'n': public_key[1]}
        priv_dict = {'d': private_key[0], 'n': private_key[1]}

        users[username] = {
            'algorithm': 'rsa',
            'public_key': pub_dict
        }
        _save_users(users)

        priv_path = os.path.join(KEYS_DIR, f"{username}.priv")
        save_key_to_file(priv_dict, priv_path)

        print(f"[+] User '{username}' created with RSA keys.")
        print(f"    Public key saved in users.json")
        print(f"    Private key saved at {priv_path}")
        print(f"    Public key tuple (e, n): ({public_key[0]}, {public_key[1]})")

    else:
        print(f"[!] Algorithm '{alg}' not implemented yet.")

def delete_user(username):
    _ensure_storage()
    users = _load_users()

    if username not in users:
        print(f"User '{username}' does not exist.")
        return

    del users[username]
    _save_users(users)

    priv_path = os.path.join(KEYS_DIR, f"{username}.priv")
    if os.path.exists(priv_path):
        os.remove(priv_path)

    print(f"User '{username}' deleted successfully.")

def import_public_key(username, e, n):
    _ensure_storage()
    users = _load_users()

    if username in users:
        print(f"[!] User '{username}' already exists in users.json.")
        return

    users[username] = {
        'algorithm': 'rsa',
        'public_key': {
            'e': str(e),
            'n': str(n)
        }
    }
    _save_users(users)
    print(f"[+] Public key for '{username}' saved in users.json.")

def list_users():
    _ensure_storage()
    users = _load_users()

    print("\nRegistered users:")
    if not users:
        print("  No users found.")
        return

    for username, data in users.items():
        priv_path = os.path.join(KEYS_DIR, f"{username}.priv")
        status = "[local]" if os.path.exists(priv_path) else "[imported]"
        print(f"  - {username} {status} (Algorithm: {data.get('algorithm', 'unknown')})")
    print()