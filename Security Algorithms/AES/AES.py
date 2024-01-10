import binascii

# Constants for AES
BLOCK_SIZE = 16
KEY_SIZE = 16
ROUNDS = 10

# AES S-box
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# AES Rijndael Rcon values for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# AES Rijndael MixColumns matrix
MIX_COLUMN_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
]

# Helper function to get user input for plaintext and key
def get_user_input():
    # Get user input for plaintext
    plaintext = input("Enter the plaintext: ").encode()

    # Get user input for key
    key_hex = input("Enter the key (32 hex digits): ")
    if len(key_hex) != 32:
        raise ValueError("Key must be 32 hex digits.")

    key = binascii.unhexlify(key_hex)

    return plaintext, key

# Helper function to display output in hexadecimal
def hex_display(data):
    return " ".join(f"{byte:02X}" for byte in data)

# Helper function to display output in characters from hexadecimal
def char_display_hex(hex_data):
    hex_string = ''.join(f'{byte:02X}' for byte in hex_data)
    byte_array = bytes.fromhex(hex_string)
    return "".join(chr(byte) for byte in byte_array)


# Helper function to pad the input plaintext
def pad_text(plaintext):
    padding_len = BLOCK_SIZE - len(plaintext) % BLOCK_SIZE
    return plaintext + bytes([padding_len] * padding_len)

# Helper function to perform AES SubBytes operation
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]

# Helper function to perform AES ShiftRows operation
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]

# Helper function to perform AES MixColumns operation
def mix_columns(state, inverse=False):
    matrix = MIX_COLUMN_MATRIX
    if inverse:
        # For decryption, use the inverse MixColumns matrix
        matrix = [list(map(lambda x: x if x == 9 else x << 1 ^ x >> 7 * 1, col)) for col in zip(*matrix)]

    result = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = (
                matrix[i][0] * state[0][j]
                + matrix[i][1] * state[1][j]
                + matrix[i][2] * state[2][j]
                + matrix[i][3] * state[3][j]
            ) % 256
    for i in range(4):
        for j in range(4):
            state[i][j] = result[i][j]

# Helper function to perform AES AddRoundKey operation
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

# Key Expansion: Generates round keys from the original key
def key_expansion(key):
    round_keys = [list(key[i : i + 4]) for i in range(0, len(key), 4)]

    for i in range(len(round_keys), 4 * (ROUNDS + 1)):
        temp = round_keys[i - 1].copy()
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # Rotate the word
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i // 4 - 1]
        round_keys.append([a ^ b for a, b in zip(round_keys[i - 4], temp)])

    return round_keys

# Encrypts a single block of plaintext using AES
def encrypt_block(plaintext, key):
    state = [list(plaintext[i : i + 4]) for i in range(0, len(plaintext), 4)]
    round_keys = key_expansion(key)

    # Initial Round Key Addition
    add_round_key(state, round_keys[:4])

    # Main Rounds
    for i in range(1, ROUNDS):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[4 * i : 4 * (i + 1)])

    # Final Round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[4 * ROUNDS :])

    # Convert the state matrix to a flat list of bytes
    cipher = [state[i][j] for j in range(4) for i in range(4)]
    return cipher

# Decrypts a single block of ciphertext using AES
def decrypt_block(cipher, key):
    state = [list(cipher[i : i + 4]) for i in range(0, len(cipher), 4)]
    round_keys = key_expansion(key)

    # Initial Round Key Addition
    add_round_key(state, round_keys[4 * ROUNDS :])

    # Decrypts a single block of ciphertext using AES
def decrypt_block(cipher, key):
    state = [list(cipher[i : i + 4]) for i in range(0, len(cipher), 4)]
    round_keys = key_expansion(key)

    # Initial Round Key Addition
    add_round_key(state, round_keys[4 * ROUNDS :])

    # Main Rounds
    for i in range(ROUNDS - 1, 0, -1):
        shift_rows(state)
        sub_bytes(state)
        mix_columns(state, inverse=True)
        add_round_key(state, round_keys[4 * i : 4 * (i + 1)])

    # Final Round Key Addition
    shift_rows(state)
    sub_bytes(state)
    add_round_key(state, round_keys[:4])

    # Convert the state matrix to a flat list of bytes
    plaintext = [state[i][j] for j in range(4) for i in range(4)]
    return plaintext


# Main function to perform AES encryption and decryption
def aes_encrypt_decrypt(plaintext, key, encrypt=True):
    # Pad the plaintext to a multiple of the block size
    padded_text = pad_text(plaintext)

    # Determine whether to encrypt or decrypt
    if encrypt:
        process_block = encrypt_block
        print("Encryption:")
    else:
        process_block = decrypt_block
        print("Decryption:")

    # Process each block of plaintext
    for i in range(0, len(padded_text), BLOCK_SIZE):
        block = padded_text[i : i + BLOCK_SIZE]
        result_block = process_block(block, key)

        # Display the result in hexadecimal and characters
        print("\nOutput in Hexadecimal:", hex_display(result_block))

# Main program
if __name__ == "__main__":
    # Get user input for plaintext and key
    plaintext, key = get_user_input()

    # Perform AES encryption
    aes_encrypt_decrypt(plaintext, key)

    # Perform AES decryption
    aes_encrypt_decrypt(plaintext, key, encrypt=False)