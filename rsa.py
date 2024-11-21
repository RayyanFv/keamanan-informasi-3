def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None

def generate_rsa_keys():
    p = 101  # Prime 1
    q = 103  # Prime 2
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1
    d = mod_inverse(e, phi)
    return (e, n), (d, n)
def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')
    ciphertext = pow(plaintext_int, e, n)
    print(f"RSA Encrypt -> Plaintext: {plaintext}, Ciphertext: {ciphertext}")
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    print(f"RSA Decrypt -> Ciphertext: {ciphertext}, Plaintext: {plaintext}")
    return plaintext
