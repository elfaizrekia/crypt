import numpy as np
import fitz  # pip install PyMuPDF
from numpy.linalg import LinAlgError

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
MOD = len(ALPHABET)  # 27

def char_to_int(char):
    return ALPHABET.index(char.upper())

def int_to_char(index):
    return ALPHABET[index % MOD]

def preprocess_text(text):
    text = text.upper()
    return ''.join(c if c in ALPHABET else ' ' for c in text)

def pad_text(text, block_size):
    while len(text) % block_size != 0:
        text += ' '
    return text

def encrypt_hill(text, key_matrix):
    text = preprocess_text(text)
    text = pad_text(text, 3)
    vectorized = [char_to_int(c) for c in text]
    
    result = ''
    for i in range(0, len(vectorized), 3):
        block = np.array(vectorized[i:i+3])
        cipher_block = key_matrix.dot(block) % MOD
        result += ''.join(int_to_char(i) for i in cipher_block)
    return result

def mod_inverse_matrix(matrix, modulus):
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det % modulus, -1, modulus)
    matrix_mod_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int)
    ) % modulus
    return matrix_mod_inv

def decrypt_hill(cipher_text, key_matrix):
    cipher_text = preprocess_text(cipher_text)
    vectorized = [char_to_int(c) for c in cipher_text]

    inverse_matrix = mod_inverse_matrix(key_matrix, MOD)
    result = ''
    for i in range(0, len(vectorized), 3):
        block = np.array(vectorized[i:i+3])
        plain_block = inverse_matrix.dot(block) % MOD
        result += ''.join(int_to_char(i) for i in plain_block)
    return result

def extract_text_from_pdf(file_path):
    doc = fitz.open(file_path)
    text = ''
    for page in doc:
        text += page.get_text()
    return text
