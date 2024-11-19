IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5, 4, 5,
     6, 7, 8, 9, 8, 9, 10, 11,
     12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27,
     28, 29, 28, 29, 30, 31, 32, 1]

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute(block, table):
    return [block[x - 1] for x in table]

def left_shift(block, num_shifts):
    return block[num_shifts:] + block[:num_shifts]

def s_box_substitution(expanded_half_block):
    sbox_output = []
    for i in range(8):
        block = expanded_half_block[i * 6:(i + 1) * 6]
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        sbox_value = S_BOX[i][row][col]
        sbox_output += [int(x) for x in f"{sbox_value:04b}"]
    return sbox_output

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def key_generation(key):
    key = permute(key, PC1)
    left, right = key[:28], key[28:]
    round_keys = []
    for shift in SHIFT:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        combined_key = left + right
        round_key = permute(combined_key, PC2)
        round_keys.append(round_key)
    return round_keys

def des_encryption(plain_text, round_keys):
    plain_text = permute(plain_text, IP)
    left, right = plain_text[:32], plain_text[32:]
    for round_key in round_keys:
        expanded_right = permute(right, E)
        xor_output = xor(expanded_right, round_key)
        sbox_output = s_box_substitution(xor_output)
        permuted_output = permute(sbox_output, P)
        new_right = xor(left, permuted_output)
        left = right
        right = new_right
    combined_text = right + left
    cipher_text = permute(combined_text, FP)
    return cipher_text

def des_decryption(cipher_text, round_keys):
    cipher_text = permute(cipher_text, IP)
    left, right = cipher_text[:32], cipher_text[32:]
    round_keys = round_keys[::-1]
    for round_key in round_keys:
        expanded_right = permute(right, E)
        xor_output = xor(expanded_right, round_key)
        sbox_output = s_box_substitution(xor_output)
        permuted_output = permute(sbox_output, P)
        new_right = xor(left, permuted_output)
        left = right
        right = new_right
    combined_text = right + left
    plain_text = permute(combined_text, FP)
    return plain_text

def string_to_bit_array(text):
    bit_array = []
    for char in text:
        binval = bin(ord(char))[2:].zfill(8)
        bit_array.extend([int(x) for x in list(binval)])
    return bit_array

def bit_array_to_string(bit_array):
    text = ''.join([chr(int(''.join([str(bit) for bit in byte]), 2)) for byte in zip(*[iter(bit_array)]*8)])
    return text

def hex_to_bit_array(hex_str):
    bit_array = []
    for char in hex_str:
        binval = bin(int(char, 16))[2:].zfill(4)
        bit_array.extend([int(x) for x in binval])
    return bit_array

def bit_array_to_hex(bit_array):
    hex_str = ''
    for i in range(0, len(bit_array), 4):
        hex_str += hex(int(''.join([str(x) for x in bit_array[i:i+4]]), 2))[2:].upper()
    return hex_str

def pad_message(message, block_size=64):
    padding_len = block_size - (len(message) * 8 % block_size) // 8
    padded_message = message + chr(padding_len) * padding_len
    return padded_message

def unpad_message(message):
    padding_len = ord(message[-1])
    return message[:-padding_len]

def encrypt_long_text(plain_text, round_keys):
    plain_text = pad_message(plain_text)
    encrypted_text = ""
    for i in range(0, len(plain_text), 8):
        block = plain_text[i:i+8]
        plain_bits = string_to_bit_array(block)
        cipher_bits = des_encryption(plain_bits, round_keys)
        encrypted_text += bit_array_to_hex(cipher_bits)
    return encrypted_text

def decrypt_long_text(cipher_text, round_keys):
    decrypted_text = ""
    for i in range(0, len(cipher_text), 16):
        block = cipher_text[i:i+16]
        cipher_bits = hex_to_bit_array(block)
        plain_bits = des_decryption(cipher_bits, round_keys)
        decrypted_text += bit_array_to_string(plain_bits)
    return unpad_message(decrypted_text)


    