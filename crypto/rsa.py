# rsa.py
import random
from utils import gcd, is_prime, modexp, modinv, int_to_text, text_to_int
"""
RSA Algorithm Implementation (Crypto101)

This file implements:
1. Key generation
2. Encryption
3. Decryption
"""

# Import necessary libraries
# (you might use 'random', 'math', or 'sympy' for prime generation)

# Utility functions
# - gcd(a, b)
# - modinv(a, m)
# - is_prime(n)  (optional for prime testing)

# Key Generation
def generate_keypair(bit_length):
    """
    Generate RSA key pair of given bit length.
    Returns (public_key, private_key).
    Each key is a tuple (exponent, n).
    """
    # 1. Choose two large primes p and q
    # 2. Compute n = p * q
    # 3. Compute phi(n) = (p-1)*(q-1)
    # 4. Choose e such that gcd(e, phi(n)) == 1
    # 5. Compute d ≡ e⁻¹ mod phi(n)
    # 6. Return (e, n), (d, n)
    def generate_prime_candidate(bits):
        return random.getrandbits(bits) | (1 << (bits - 1)) | 1  
    def find_prime(bits):
        candidate = generate_prime_candidate(bits)
        while not is_prime(candidate):
            candidate = generate_prime_candidate(bits)
        return candidate
    p = find_prime(bit_length)
    q = find_prime(bit_length)
    while q == p:
        q = find_prime(bit_length)
    n = p * q
    phi_n = (p-1) * (q-1)
    e = 65537
    while gcd(e, phi_n) != 1:
        e = random.randrange(3, phi_n, 2)
    d = modinv(e, phi_n)
    return ((e, n), (d, n))
# Encryption
def encrypt(message, public_key):
    """
    Encrypt an integer message with the public key.
    Returns ciphertext.
    """
    e, n = public_key
    c = modexp(message, e, n)
    return c

# Decryption
def decrypt(ciphertext, private_key):
    """
    Decrypt an integer ciphertext with the private key.
    Returns original message.
    """
    d, n = private_key
    m = modexp(ciphertext, d, n)
    # m = c^d mod n
    return m

# Example usage
if __name__ == "__main__":
    # 1. Generate keys
    # 2. Pick a message (as an integer)
    # 3. Encrypt it
    # 4. Decrypt it
    # 5. Print results
    public_key, private_key = generate_keypair(1024)
    message_text = input("Input a short message: ")
    message_int = text_to_int(message_text)
    
    c = encrypt(message_int, public_key)
    print("Ciphertext:", c)
    
    decrypted_int = decrypt(c, private_key)
    decrypted_text = int_to_text(decrypted_int)
    
    print("Decrypted text:", decrypted_text)
