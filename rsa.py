def gcd(a, b):
  while b:
    a, b = b, a % b
  return a

def mod_inverse(e, phi):
  for d in range(1, phi):
    if (e * d) % phi == 1:
      return d
  return None

def rsa_generate_keys():
  # Menggunakan p dan q yang sudah ditentukan (tidak lagi random)
  p = 1151
  q = 3457
  n = p * q
  phi = (p - 1) * (q - 1)
  
  # Memilih e yang relatif prima dengan phi
  e = 2
  while gcd(e, phi) != 1:
    e += 1
  
  d = mod_inverse(e, phi)
  public_key = (e, n)
  private_key = (d, n)
  return public_key, private_key

def rsa_encrypt(public_key, plaintext):
  e, n = public_key
  ciphertext = [pow(ord(char), e, n) for char in plaintext]
  return ciphertext

def rsa_decrypt(private_key, ciphertext):
  d, n = private_key
  plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
  return plaintext
