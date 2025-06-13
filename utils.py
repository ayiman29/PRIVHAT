import random
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
    
    
def extended_gcd_iterative(a, b):
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return (a, x0, y0)

def modinv(a, m):
    g, x, y = extended_gcd_iterative(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def modexp(base, exp, mod):
    result = 1
    base = base % mod 

    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    
    return result

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = modexp(a, d, n)  
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  
    
    return True  

def int_to_text(number):
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder='big').decode('utf-8')

def text_to_int(text):
    return int.from_bytes(text.encode('utf-8'), byteorder='big')