#!/usr/bin/env python3
"""
Crypto Toolkit - A comprehensive tool for solving cryptographic and encoding challenges
"""

import base64
import binascii
import string
import re
from urllib.parse import quote, unquote
from collections import Counter
import math
import itertools
import codecs
from typing import List, Dict, Tuple, Any, Callable
import json


# ============================================================================
# TRANSFORMERS - String transformations, substitutions, rotations
# ============================================================================

class Transformers:
    """Methods for transforming and manipulating strings"""
    
    
    @staticmethod
    def remove_bell_chars(text):
        """Remove audio bell characters from text"""
        if isinstance(text, str):
            # Remove bell characters: \x07 (BEL), \a
            return text.replace('\x07', '').replace('\a', '').replace('\b', '')
        return text

    @staticmethod
    def caesar_cipher(text, shift):
        """Apply Caesar cipher with given shift"""
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            elif char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rot13(text):
        """Apply ROT13 transformation"""
        return Transformers.caesar_cipher(text, 13)
    
    @staticmethod
    def rot5(text):
        """Apply ROT5 to digits only"""
        result = []
        for char in text:
            if char.isdigit():
                result.append(str((int(char) + 5) % 10))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rot18(text):
        """Apply ROT13 to letters and ROT5 to digits"""
        return Transformers.rot5(Transformers.rot13(text))
    
    @staticmethod
    def rot47(text):
        """Apply ROT47 to all printable ASCII characters"""
        result = []
        for char in text:
            if 33 <= ord(char) <= 126:
                result.append(chr(33 + ((ord(char) - 33 + 47) % 94)))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def reverse_string(text):
        """Reverse the string"""
        return text[::-1]
    
    @staticmethod
    def reverse_words(text):
        """Reverse each word individually"""
        return ' '.join(word[::-1] for word in text.split())
    
    @staticmethod
    def atbash(text):
        """Apply Atbash cipher (A->Z, B->Y, etc.)"""
        result = []
        for char in text:
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            elif char.islower():
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def substitution_cipher(text, mapping):
        """Apply custom substitution cipher using a mapping dictionary"""
        result = []
        for char in text:
            result.append(mapping.get(char, char))
        return ''.join(result)
    
    @staticmethod
    def remove_spaces(text):
        """Remove all whitespace from text"""
        return text.replace(' ', '').replace('\t', '').replace('\n', '')
    
    @staticmethod
    def swap_case(text):
        """Swap uppercase and lowercase"""
        return text.swapcase()
    
    @staticmethod
    def xor_with_key(text, key):
        """XOR text with a key (repeating if needed)"""
        if isinstance(text, str):
            text = text.encode()
        if isinstance(key, str):
            key = key.encode()
        
        result = []
        for i, byte in enumerate(text):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
    
    @staticmethod
    def xor_bruteforce(data):
        """Try all single-byte XOR keys (0-255)"""
        if isinstance(data, str):
            data = data.encode()
        
        results = {}
        for key in range(256):
            try:
                decoded = bytes([byte ^ key for byte in data])
                decoded_str = decoded.decode('utf-8', errors='ignore')
                if decoded_str:
                    results[key] = decoded_str
            except:
                pass
        return results
    
    @staticmethod
    def transpose(text, key):
        """Columnar transposition cipher"""
        text = text.replace(' ', '')
        cols = len(key)
        rows = (len(text) + cols - 1) // cols
        
        padded_text = text + 'X' * (rows * cols - len(text))
        matrix = [padded_text[i:i+cols] for i in range(0, len(padded_text), cols)]
        
        sorted_key = sorted(enumerate(key), key=lambda x: x[1])
        result = []
        for col_idx, _ in sorted_key:
            for row in matrix:
                if col_idx < len(row):
                    result.append(row[col_idx])
        
        return ''.join(result)
    
    @staticmethod
    def rail_fence(text, rails):
        """Rail fence cipher encryption"""
        if rails < 2:
            return text
        
        text = text.replace(' ', '')
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join([''.join(rail) for rail in fence])
    
    @staticmethod
    def rail_fence_decode(text, rails):
        """Rail fence cipher decryption"""
        if rails < 2:
            return text
        
        text = text.replace(' ', '')
        fence = [[] for _ in range(rails)]
        rail_lengths = [0] * rails
        
        # Calculate rail lengths
        rail = 0
        direction = 1
        for _ in range(len(text)):
            rail_lengths[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        # Fill fence with characters
        idx = 0
        for i in range(rails):
            fence[i] = list(text[idx:idx + rail_lengths[i]])
            idx += rail_lengths[i]
        
        # Read in zigzag pattern
        result = []
        rail = 0
        direction = 1
        for _ in range(len(text)):
            if fence[rail]:
                result.append(fence[rail].pop(0))
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join(result)
    
    @staticmethod
    def vigenere_encrypt(text, key):
        """Vigenere cipher encryption"""
        key = key.upper()
        result = []
        key_idx = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def vigenere_decrypt(text, key):
        """Vigenere cipher decryption"""
        key = key.upper()
        result = []
        key_idx = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def bacon_decode(text):
        """Decode Bacon cipher (A/B or 0/1 patterns)"""
        bacon_map = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        return Transformers._bacon_decode_words(
            text, lambda group: bacon_map.get(group, '?'))
    
    @staticmethod
    def _bacon_decode_words(text, decode_group):
        """
        Shared Bacon decoding: normalise to A/B and decode 5-symbol groups.
        If whitespace splits the input into chunks that are all multiples of 5 and
        at least one chunk is longer than 5, the whitespace marks word boundaries
        and is kept in the output ('aaabbaaaaabbaaa abbba...' -> 'DAY ONE ...').
        Spaces between every single group are just formatting and are dropped.
        """
        text = text.upper().replace('0', 'A').replace('1', 'B')
        chunks = [''.join(c for c in chunk if c in 'AB') for chunk in text.split()]
        chunks = [chunk for chunk in chunks if chunk]
        
        def decode(ab):
            return ''.join(decode_group(ab[i:i+5]) for i in range(0, len(ab) - 4, 5))
        
        if (len(chunks) > 1 and all(len(chunk) % 5 == 0 for chunk in chunks)
                and any(len(chunk) > 5 for chunk in chunks)):
            return ' '.join(decode(chunk) for chunk in chunks)
        return decode(''.join(chunks))
    
    @staticmethod
    def all_caesar_shifts(text):
        """Return all 26 possible Caesar cipher shifts"""
        results = {}
        for shift in range(26):
            results[shift] = Transformers.caesar_cipher(text, shift)
        return results
    
    @staticmethod
    def all_rail_fence(text, max_rails=10):
        """Try rail fence with different rail counts"""
        results = {}
        for rails in range(2, min(max_rails + 1, len(text))):
            try:
                results[rails] = Transformers.rail_fence_decode(text, rails)
            except:
                pass
        return results
    
    @staticmethod
    def leetspeak_decode(text):
        """Decode leetspeak (1337 5p34k)"""
        leet_map = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '9': 'g', '@': 'a', '|': 'i',
            '!': 'i', '$': 's', '+': 't', '|<': 'k', '|>': 'p',
            '|-|': 'h', '|_': 'l', '|\\|': 'n', '|)': 'd', '><': 'x',
            '||': 'n', '/\\': 'a', '\\/': 'v', '}{': 'h'
        }
        
        result = text
        for leet, normal in sorted(leet_map.items(), key=lambda x: -len(x[0])):
            result = result.replace(leet, normal)
        
        return result
    
    @staticmethod
    def letter_to_number(text):
        """Convert letters to numbers (A=1, B=2, etc)"""
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(str(ord(char) - ord('A') + 1))
                else:
                    result.append(str(ord(char) - ord('a') + 1))
            else:
                result.append(char)
        return ' '.join(result)
    
    @staticmethod
    def number_to_letter(text):
        """Convert numbers to letters (1=A, 2=B, etc)"""
        numbers = re.findall(r'\d+', text)
        result = []
        for num in numbers:
            n = int(num)
            if 1 <= n <= 26:
                result.append(chr(ord('A') + n - 1))
        return ''.join(result)
    
    @staticmethod
    def affine_cipher(text, a=5, b=8):
        """Affine cipher: E(x) = (ax + b) mod 26"""
        result = []
        for char in text:
            if char.isupper():
                x = ord(char) - ord('A')
                result.append(chr(((a * x + b) % 26) + ord('A')))
            elif char.islower():
                x = ord(char) - ord('a')
                result.append(chr(((a * x + b) % 26) + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def affine_decrypt(text, a=5, b=8):
        """Affine cipher decryption"""
        # Find modular multiplicative inverse of a
        def mod_inverse(a, m=26):
            for i in range(1, m):
                if (a * i) % m == 1:
                    return i
            return None
        
        a_inv = mod_inverse(a)
        if not a_inv:
            return text
        
        result = []
        for char in text:
            if char.isupper():
                y = ord(char) - ord('A')
                result.append(chr(((a_inv * (y - b)) % 26) + ord('A')))
            elif char.islower():
                y = ord(char) - ord('a')
                result.append(chr(((a_inv * (y - b)) % 26) + ord('a')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def playfair_encode(text, key="KEYWORD"):
        """Playfair cipher encoding"""
        # Create 5x5 matrix from key
        key = key.upper().replace('J', 'I')
        matrix = []
        used = set()
        
        # Add key letters
        for char in key:
            if char.isalpha() and char not in used:
                matrix.append(char)
                used.add(char)
        
        # Add remaining letters
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # No J
            if char not in used:
                matrix.append(char)
                used.add(char)
        
        # Create position lookup
        pos = {matrix[i]: (i // 5, i % 5) for i in range(25)}
        
        # Prepare text
        text = text.upper().replace('J', 'I').replace(' ', '')
        text = ''.join(c for c in text if c.isalpha())
        
        # Split into digraphs
        pairs = []
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                pairs.append((a, 'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        
        # Encode pairs
        result = []
        for a, b in pairs:
            row1, col1 = pos[a]
            row2, col2 = pos[b]
            
            if row1 == row2:  # Same row
                result.append(matrix[row1 * 5 + (col1 + 1) % 5])
                result.append(matrix[row2 * 5 + (col2 + 1) % 5])
            elif col1 == col2:  # Same column
                result.append(matrix[((row1 + 1) % 5) * 5 + col1])
                result.append(matrix[((row2 + 1) % 5) * 5 + col2])
            else:  # Rectangle
                result.append(matrix[row1 * 5 + col2])
                result.append(matrix[row2 * 5 + col1])
        
        return ''.join(result)
    
    @staticmethod
    def polybius_square(text, decode=False):
        """Polybius square cipher (encodes letters to number pairs)"""
        # Standard 5x5 grid (I/J combined)
        grid = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        if not decode:
            # Encode: letters to numbers
            text = text.upper().replace('J', 'I')
            result = []
            for char in text:
                if char in grid:
                    pos = grid.index(char)
                    row, col = pos // 5 + 1, pos % 5 + 1
                    result.append(f"{row}{col}")
                else:
                    result.append(char)
            return ' '.join(result)
        else:
            # Decode: numbers to letters
            pairs = text.replace(' ', '')
            result = []
            for i in range(0, len(pairs), 2):
                if i+1 < len(pairs) and pairs[i].isdigit() and pairs[i+1].isdigit():
                    row, col = int(pairs[i]) - 1, int(pairs[i+1]) - 1
                    if 0 <= row < 5 and 0 <= col < 5:
                        result.append(grid[row * 5 + col])
            return ''.join(result)
    
    @staticmethod
    def beaufort_cipher(text, key="KEY"):
        """Beaufort cipher (reciprocal, like Vigenere but different)"""
        key = key.upper()
        result = []
        key_idx = 0
        
        for char in text:
            if char.isalpha():
                key_char = key[key_idx % len(key)]
                if char.isupper():
                    # Beaufort: C = (K - P) mod 26
                    result.append(chr(((ord(key_char) - ord(char)) % 26) + ord('A')))
                else:
                    result.append(chr(((ord(key_char.lower()) - ord(char)) % 26) + ord('a')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def gronsfeld_cipher(text, key="123"):
        """Gronsfeld cipher (Vigenere with numeric key)"""
        result = []
        key_idx = 0
        
        for char in text:
            if char.isalpha():
                shift = int(key[key_idx % len(key)])
                if char.isupper():
                    result.append(chr(((ord(char) - ord('A') + shift) % 26) + ord('A')))
                else:
                    result.append(chr(((ord(char) - ord('a') + shift) % 26) + ord('a')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def porta_cipher(text, key="KEY"):
        """Porta cipher (polyalphabetic with 13 alphabets)"""
        # Porta uses 13 alphabets (A/B use same, C/D use same, etc.)
        key = key.upper()
        result = []
        key_idx = 0
        
        alphabets = [
            "NOPQRSTUVWXYZABCDEFGHIJKLM",  # A,B
            "OPQRSTUVWXYZMNABCDEFGHIJKL",  # C,D
            "PQRSTUVWXYZNMABCDEFGHIJKLO",  # E,F
            "QRSTUVWXYZPONMLKJIHGFEDCBA",  # G,H
            "RSTUVWXYZQPONMLKJIHGFEDCBA",  # I,J
            "STUVWXYZRQPONMLKJIHGFEDCBA",  # K,L
            "TUVWXYZSRQPONMLKJIHGFEDCBA",  # M,N
            "UVWXYZTSRQPONMLKJIHGFEDCBA",  # O,P
            "VWXYZUTSRQPONMLKJIHGFEDCBA",  # Q,R
            "WXYZVU TSRQPONMLKJIHGFEDCBA",  # S,T
            "XYZWVUTSRQPONMLKJIHGFEDCBA",  # U,V
            "YZXWVUTSRQPONMLKJIHGFEDCBA",  # W,X
            "ZYXWVUTSRQPONMLKJIHGFEDCBA",  # Y,Z
        ]
        
        for char in text:
            if char.isalpha():
                key_char = key[key_idx % len(key)]
                alphabet_idx = (ord(key_char) - ord('A')) // 2
                
                plain_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                cipher_alphabet = alphabets[alphabet_idx]
                
                if char.isupper():
                    pos = plain_alphabet.index(char)
                    result.append(cipher_alphabet[pos])
                else:
                    pos = plain_alphabet.index(char.upper())
                    result.append(cipher_alphabet[pos].lower())
                
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    

    @staticmethod
    def trithemius_cipher(text, decrypt=False):
        """Trithemius cipher - progressive Caesar shift (0, 1, 2, 3...)"""
        result = []
        for i, char in enumerate(text):
            if char.isalpha():
                shift = i if not decrypt else -i
                base = ord('A') if char.isupper() else ord('a')
                shifted = chr((ord(char) - base + shift) % 26 + base)
                result.append(shifted)
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def trithemius_decrypt(text):
        """Decrypt Trithemius cipher"""
        return Transformers.trithemius_cipher(text, decrypt=True)
    
    @staticmethod
    def all_gronsfeld_decrypt(text):
        """Try many Gronsfeld keys"""
        results = {}
        keys = ['1', '2', '3', '12', '23', '123', '321', '1234', '4321', '12345',
                '111', '222', '333', '1111', '2222', '1212', '2323', '1357', '2468',
                '101', '102', '201', '301', '12321', '123321']
        for key in keys:
            try:
                decoded = Transformers.gronsfeld_cipher(text, key)
                if decoded and decoded != text:
                    results[f'gronsfeld_{key}'] = decoded
            except:
                pass
        return results
    
    @staticmethod
    def all_porta_decrypt(text):
        """Try Porta cipher with many keys"""
        results = {}
        common_keys = ['KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'FLAG',
                       'CRYPTO', 'PORTA', 'ALPHABET', 'HIDDEN']
        for key in common_keys:
            try:
                decoded = Transformers.porta_cipher(text, key)
                if decoded and decoded != text:
                    results[f'porta_{key}'] = decoded
            except:
                pass
        return results
    
    @staticmethod
    def all_affine_decrypt(text):
        """Try all valid Affine parameters (312 combinations)"""
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        results = {}
        for a in valid_a:
            for b in range(26):
                try:
                    decoded = Transformers.affine_decrypt(text, a, b)
                    if decoded and decoded != text:
                        results[f'affine_{a}_{b}'] = decoded
                except:
                    pass
        return results
    
    def autokey_cipher(text, key="KEY", decode=False):
        """Autokey cipher (key extends with plaintext/ciphertext)"""
        key = key.upper()
        result = []
        
        if not decode:
            # Encoding: key extends with plaintext
            extended_key = key
            for i, char in enumerate(text):
                if char.isalpha():
                    key_char = extended_key[i] if i < len(extended_key) else 'A'
                    shift = ord(key_char) - ord('A')
                    
                    if char.isupper():
                        encoded = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
                        result.append(encoded)
                        extended_key += char  # Add plaintext to key
                    else:
                        encoded = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
                        result.append(encoded)
                        extended_key += char.upper()
                else:
                    result.append(char)
        else:
            # Decoding: key extends with decrypted text
            extended_key = key
            for i, char in enumerate(text):
                if char.isalpha():
                    key_char = extended_key[i] if i < len(extended_key) else 'A'
                    shift = ord(key_char) - ord('A')
                    
                    if char.isupper():
                        decoded = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
                        result.append(decoded)
                        extended_key += decoded  # Add plaintext to key
                    else:
                        decoded = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
                        result.append(decoded)
                        extended_key += decoded.upper()
                else:
                    result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def bifid_cipher(text, key="KEYWORD", period=5):
        """Bifid cipher (fractionating cipher using Polybius square)"""
        # Create keyed Polybius square
        key = key.upper().replace('J', 'I')
        square = []
        used = set()
        
        for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if char.isalpha() and char not in used:
                square.append(char)
                used.add(char)
        
        # Create lookup tables
        char_to_pos = {square[i]: (i // 5, i % 5) for i in range(25)}
        pos_to_char = {(i // 5, i % 5): square[i] for i in range(25)}
        
        # Prepare text
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())
        
        # Split into coordinates
        rows = []
        cols = []
        for char in text:
            if char in char_to_pos:
                row, col = char_to_pos[char]
                rows.append(row)
                cols.append(col)
        
        # Combine and split by period
        combined = rows + cols
        result = []
        
        for i in range(0, len(combined), 2):
            if i+1 < len(combined):
                row, col = combined[i], combined[i+1]
                if (row, col) in pos_to_char:
                    result.append(pos_to_char[(row, col)])
        
        return ''.join(result)
    
    @staticmethod
    def gray_code_to_binary(gray):
        """Convert Gray code to binary"""
        if isinstance(gray, str):
            gray = int(gray, 2)
        
        binary = gray
        while gray > 0:
            gray >>= 1
            binary ^= gray
        
        return binary
    
    @staticmethod
    def binary_to_gray_code(binary):
        """Convert binary to Gray code"""
        if isinstance(binary, str):
            binary = int(binary, 2)
        
        return binary ^ (binary >> 1)
    
    @staticmethod
    def gray_code_decode(text):
        """Decode Gray code text"""
        try:
            # Remove spaces and convert
            binary_str = text.replace(' ', '')
            
            # Process in 8-bit chunks
            result = []
            for i in range(0, len(binary_str), 8):
                chunk = binary_str[i:i+8]
                if len(chunk) == 8:
                    gray = int(chunk, 2)
                    binary = Transformers.gray_code_to_binary(gray)
                    result.append(binary)
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def bit_reversal(text):
        """Reverse bits in each byte"""
        if isinstance(text, str):
            text = text.encode()
        
        result = []
        for byte in text:
            # Reverse bits
            reversed_byte = int('{:08b}'.format(byte)[::-1], 2)
            result.append(reversed_byte)
        
        return bytes(result).decode('utf-8', errors='ignore')
    
    @staticmethod
    def reverse_chunks(text, chunk_size=2):
        """Reverse text in chunks"""
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        return ''.join(chunks[::-1])
    
    @staticmethod
    def reverse_each_chunk(text, chunk_size=2):
        """Reverse each chunk individually"""
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        return ''.join(chunk[::-1] for chunk in chunks)
    
    @staticmethod
    def alternating_case(text):
        """Alternate between upper and lowercase"""
        result = []
        upper = True
        for char in text:
            if char.isalpha():
                result.append(char.upper() if upper else char.lower())
                upper = not upper
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def columnar_transposition_decode(text, key):
        """Decode columnar transposition"""
        cols = len(key)
        rows = len(text) // cols
        
        # Get column order
        sorted_key = sorted(enumerate(key), key=lambda x: x[1])
        
        # Fill columns
        columns = {}
        idx = 0
        for col_idx, _ in sorted_key:
            columns[col_idx] = text[idx:idx+rows]
            idx += rows
        
        # Read row by row
        result = []
        for row in range(rows):
            for col in range(cols):
                if row < len(columns.get(col, '')):
                    result.append(columns[col][row])
        
        return ''.join(result)
    
    @staticmethod
    def scytale_decode(text, rails):
        """Scytale cipher decode (ancient transposition)"""
        if rails < 2:
            return text
        
        rows = (len(text) + rails - 1) // rails
        
        # Fill matrix column by column
        matrix = [[''] * rails for _ in range(rows)]
        idx = 0
        
        for col in range(rails):
            for row in range(rows):
                if idx < len(text):
                    matrix[row][col] = text[idx]
                    idx += 1
        
        # Read row by row
        result = []
        for row in matrix:
            result.extend(row)
        
        return ''.join(result)
    
    @staticmethod
    def route_cipher_spiral(text, size=None):
        """Route cipher - spiral inward reading"""
        if not size:
            size = int(len(text) ** 0.5) + 1
        
        # Pad text
        padded = text + 'X' * (size * size - len(text))
        
        # Create matrix
        matrix = [['' for _ in range(size)] for _ in range(size)]
        idx = 0
        
        # Fill spiral
        top, bottom, left, right = 0, size-1, 0, size-1
        
        while top <= bottom and left <= right:
            # Right
            for i in range(left, right + 1):
                if idx < len(padded):
                    matrix[top][i] = padded[idx]
                    idx += 1
            top += 1
            
            # Down
            for i in range(top, bottom + 1):
                if idx < len(padded):
                    matrix[i][right] = padded[idx]
                    idx += 1
            right -= 1
            
            # Left
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if idx < len(padded):
                        matrix[bottom][i] = padded[idx]
                        idx += 1
                bottom -= 1
            
            # Up
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if idx < len(padded):
                        matrix[i][left] = padded[idx]
                        idx += 1
                left += 1
        
        # Read row by row
        return ''.join(''.join(row) for row in matrix)
    
    @staticmethod
    def bacon_decode_variants(text):
        """Try multiple Bacon cipher variants (A/B, 0/1, forward/reverse)"""
        results = {}
        
        # Standard A/B
        try:
            results['AB_forward'] = Transformers.bacon_decode(text)
        except:
            pass
        
        # Flipped B/A (also flips 0/1)
        try:
            flipped = text.upper().translate(str.maketrans('AB01', 'BA10'))
            results['BA_flipped'] = Transformers.bacon_decode(flipped)
        except:
            pass
        
        # Reversed
        try:
            results['AB_reversed'] = Transformers.bacon_decode(text[::-1])
        except:
            pass
        
        # Original 24-letter alphabet (I=J, U=V), normal and flipped
        try:
            results['24_letter'] = Transformers.bacon_decode_24(text)
            results['24_letter_flipped'] = Transformers.bacon_decode_24(
                text.upper().translate(str.maketrans('AB01', 'BA10')))
        except:
            pass
        
        return {k: v for k, v in results.items() if v and len(v) > 0}
    
    @staticmethod
    def bacon_decode_24(text):
        """Decode the original 24-letter Bacon cipher, where I/J and U/V share a code"""
        alphabet = 'ABCDEFGHIKLMNOPQRSTUWXYZ'  # no J, no V
        
        def decode_group(group):
            index = int(group.replace('A', '0').replace('B', '1'), 2)
            return alphabet[index] if index < len(alphabet) else '?'
        
        return Transformers._bacon_decode_words(text, decode_group)
    
    @staticmethod
    def bacon_decode_digit_letter(text):
        """Bacon cipher using digit/letter classification (Digit=1, Letter=0)"""
        # Convert to binary based on char type
        binary = ''.join('1' if c.isdigit() else '0' for c in text)
        
        # Drop last bit if needed to make divisible by 5
        if len(binary) % 5 != 0:
            binary = binary[:-(len(binary) % 5)]
        
        # Bacon 26-letter alphabet
        bacon_26 = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        # Try both 0=A,1=B and 0=B,1=A
        results = {}
        
        for interpretation in ['0=A', '0=B']:
            if interpretation == '0=A':
                processed = binary.replace('0', 'A').replace('1', 'B')
            else:
                processed = binary.replace('0', 'B').replace('1', 'A')
            
            groups = [processed[i:i+5] for i in range(0, len(processed), 5)]
            decoded = ''.join(bacon_26.get(g, '?') for g in groups if len(g) == 5)
            
            if '?' not in decoded:
                results[interpretation] = decoded
        
        return results
    
    @staticmethod
    def variable_rot_decode(text):
        """Variable ROT where digits set rotation amount"""
        result = []
        current_rot = 0
        
        for char in text:
            if char.isdigit():
                current_rot = int(char)
            elif char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                rotated = chr((ord(char) - base + current_rot) % 26 + base)
                result.append(rotated)
            else:
                result.append(char)
        
        return ''.join(result)


    @staticmethod
    def adfgx_cipher_decrypt(text, key="KEYWORD"):
        """ADFGX cipher (5x5 grid, uses letters ADFGX)"""
        # ADFGX uses 5x5 grid (combines I/J)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters, no J
        key_clean = ''.join(dict.fromkeys(key.upper().replace('J', 'I')))
        key_clean = ''.join(c for c in key_clean if c in alphabet)
        remaining = ''.join(c for c in alphabet if c not in key_clean)
        grid_alphabet = key_clean + remaining
        
        # Create grid
        adfgx = "ADFGX"
        grid = {}
        rev_grid = {}
        for i, letter in enumerate(grid_alphabet):
            row, col = divmod(i, 5)
            coord = adfgx[row] + adfgx[col]
            grid[letter] = coord
            rev_grid[coord] = letter
        
        # Decode (remove spaces, pair up)
        text_clean = text.upper().replace(' ', '')
        result = []
        for i in range(0, len(text_clean), 2):
            if i+1 < len(text_clean):
                pair = text_clean[i:i+2]
                if pair in rev_grid:
                    result.append(rev_grid[pair])
        
        return ''.join(result)
    
    @staticmethod
    def pigpen_decode(text):
        """Pigpen/Masonic cipher decoder"""
        # Basic pigpen mappings (simplified, multiple variants exist)
        pigpen_map = {
            '⌐': 'A', '¬': 'B', '⌙': 'C',
            '⌊': 'D', '⌋': 'E', '⌈': 'F',
            '⌉': 'G', '⌞': 'H', '⌟': 'I',
            '⌜': 'J', '⌝': 'K', '⊏': 'L',
            '⊐': 'M', '⊓': 'N', '⊔': 'O',
            '•⌐': 'P', '•¬': 'Q', '•⌙': 'R',
            '•⌊': 'S', '•⌋': 'T', '•⌈': 'U',
            '•⌉': 'V', '•⌞': 'W', '•⌟': 'X',
            '•⌜': 'Y', '•⌝': 'Z',
        }
        
        result = []
        for symbol in text:
            if symbol in pigpen_map:
                result.append(pigpen_map[symbol])
            else:
                result.append(symbol)
        
        return ''.join(result)
    
    @staticmethod
    def keyed_caesar_decrypt(text, key="KEY"):
        """Caesar cipher with keyword offset"""
        if not key:
            return text
        
        # Use first letter of key as offset
        key_char = key[0].upper()
        shift = ord(key_char) - ord('A')
        
        return Transformers.caesar_cipher(text, -shift)
    
    @staticmethod
    def beaufort_autokey_decrypt(text, key="KEY"):
        """Beaufort autokey cipher"""
        if not key:
            return text
        
        key_clean = ''.join(c for c in key.upper() if c.isalpha())
        text_clean = text.upper()
        
        result = []
        key_index = 0
        
        for char in text_clean:
            if char.isalpha():
                # Beaufort: decrypt = (key - ciphertext) mod 26
                if key_index < len(key_clean):
                    key_char = key_clean[key_index]
                else:
                    # Autokey: use plaintext as key
                    key_char = result[key_index - len(key_clean)]
                
                key_val = ord(key_char) - ord('A')
                char_val = ord(char) - ord('A')
                plain_val = (key_val - char_val) % 26
                plain_char = chr(plain_val + ord('A'))
                result.append(plain_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def variant_beaufort_decrypt(text, key="KEY"):
        """Variant Beaufort cipher (reverse direction)"""
        if not key:
            return text
        
        key_clean = ''.join(c for c in key.upper() if c.isalpha())
        text_clean = text.upper()
        
        result = []
        key_index = 0
        
        for char in text_clean:
            if char.isalpha():
                key_char = key_clean[key_index % len(key_clean)]
                key_val = ord(key_char) - ord('A')
                char_val = ord(char) - ord('A')
                # Variant Beaufort: decrypt = (ciphertext - key) mod 26
                plain_val = (char_val - key_val) % 26
                result.append(chr(plain_val + ord('A')))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def vigenere_autokey_decrypt(text, key="KEY"):
        """Vigenere autokey cipher"""
        if not key:
            return text
        
        key_clean = ''.join(c for c in key.upper() if c.isalpha())
        text_clean = text.upper()
        
        result = []
        key_index = 0
        
        for char in text_clean:
            if char.isalpha():
                if key_index < len(key_clean):
                    key_char = key_clean[key_index]
                else:
                    # Autokey: use plaintext as key
                    key_char = result[key_index - len(key_clean)]
                
                key_val = ord(key_char) - ord('A')
                char_val = ord(char) - ord('A')
                plain_val = (char_val - key_val) % 26
                plain_char = chr(plain_val + ord('A'))
                result.append(plain_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)


    @staticmethod
    def all_beaufort_autokey_decrypt(text):
        """Brute force Beaufort autokey with common keys"""
        results = []
        common_keys = ['KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'CRYPTO', 'FLAG',
                       'HIDDEN', 'MESSAGE', 'ENIGMA', 'BSIDES', 'CTF', 'SECURITY']
        
        for key in common_keys:
            try:
                decoded = Transformers.beaufort_autokey_decrypt(text, key)
                if decoded and decoded != text:
                    results.append({'method': f'beaufort_autokey({key})', 'text': decoded})
            except:
                pass
        
        return results
    
    @staticmethod
    def all_variant_beaufort_decrypt(text):
        """Brute force Variant Beaufort with common keys"""
        results = []
        common_keys = ['KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'CRYPTO', 'FLAG',
                       'HIDDEN', 'MESSAGE', 'ENIGMA', 'BSIDES', 'CTF', 'SECURITY']
        
        for key in common_keys:
            try:
                decoded = Transformers.variant_beaufort_decrypt(text, key)
                if decoded and decoded != text:
                    results.append({'method': f'variant_beaufort({key})', 'text': decoded})
            except:
                pass
        
        return results
    
    @staticmethod
    def all_vigenere_autokey_decrypt(text):
        """Brute force Vigenere autokey with common keys"""
        results = []
        common_keys = ['KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'CRYPTO', 'FLAG',
                       'HIDDEN', 'MESSAGE', 'ENIGMA', 'BSIDES', 'CTF', 'SECURITY', 'LONDON',
                       'TRANSMISSION', 'DATA', 'INFO', 'WORD', 'TEXT', 'LETTER']
        
        for key in common_keys:
            try:
                decoded = Transformers.vigenere_autokey_decrypt(text, key)
                if decoded and decoded != text:
                    results.append({'method': f'vigenere_autokey({key})', 'text': decoded})
            except:
                pass
        
        return results
    
    @staticmethod
    def all_adfgx_decrypt(text):
        """Brute force ADFGX with common keys"""
        results = []
        common_keys = ['KEYWORD', 'SECRET', 'CIPHER', 'CODE', 'KEY', 'CRYPTO', 'HIDDEN']
        
        for key in common_keys:
            try:
                decoded = Transformers.adfgx_cipher_decrypt(text, key)
                if decoded and decoded != text:
                    results.append({'method': f'adfgx({key})', 'text': decoded})
            except:
                pass
        
        return results
    
    @staticmethod
    def substitution_autosolver(text):
        """Simple substitution cipher solver using frequency analysis"""
        text_clean = ''.join(c for c in text.upper() if c.isalpha())
        
        if len(text_clean) < 20:
            return []
        
        # English letter frequency (most to least common)
        eng_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
        
        # Count frequency in ciphertext
        from collections import Counter
        freq_count = Counter(text_clean)
        cipher_freq = ''.join(c for c, _ in freq_count.most_common())
        
        # Create substitution map
        sub_map = {}
        for i, cipher_char in enumerate(cipher_freq):
            if i < len(eng_freq):
                sub_map[cipher_char] = eng_freq[i]
        
        # Decode
        result = []
        for char in text.upper():
            if char in sub_map:
                result.append(sub_map[char])
            else:
                result.append(char)
        
        decoded = ''.join(result)
        
        if decoded != text.upper():
            return [{'method': 'substitution_freq_analysis', 'text': decoded}]
        
        return []


    @staticmethod
    def try_all_case_variants(text, cipher_func, key):
        """Try cipher with all case variants of key"""
        results = []
        
        if not key:
            return results
        
        # Generate case variants
        variants = [
            key.upper(),
            key.lower(),
            key.capitalize(),
            key.title(),
        ]
        
        # Add alternating case if short enough
        if len(key) <= 10:
            alt1 = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(key))
            alt2 = ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(key))
            variants.extend([alt1, alt2])
        
        # Add reversed
        variants.append(key[::-1].upper())
        variants.append(key[::-1].lower())
        
        # Try each variant
        for variant in set(variants):  # Remove duplicates
            try:
                decoded = cipher_func(text, variant)
                if decoded and decoded != text:
                    results.append({
                        'key': variant,
                        'text': decoded
                    })
            except:
                pass
        
        return results
    
    @staticmethod
    def morse_decode_variants(text):
        """Try multiple Morse code interpretations"""
        results = {}
        
        # Standard morse
        morse_map = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z',
            '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9'
        }
        
        # Try different separators
        separators = [' ', '/', '|', ',', '-', '_', '\n', '\t']
        
        for sep in separators:
            if sep in text:
                try:
                    words = text.split('  ' + sep)  # Double separator for word breaks
                    decoded_words = []
                    
                    for word in words:
                        letters = word.split(sep)
                        decoded_word = ''.join(morse_map.get(letter, '?') for letter in letters if letter)
                        if '?' not in decoded_word:
                            decoded_words.append(decoded_word)
                    
                    if decoded_words:
                        results[f'morse_sep_{repr(sep)}'] = ' '.join(decoded_words)
                except:
                    pass
        
        return results
    
    @staticmethod
    def keyboard_variants(text):
        """Try keyboard shift variants (QWERTY)"""
        keyboard_rows = {
            'qwerty': 'qwertyuiopasdfghjklzxcvbnm',
            'shifted': 'wertyuiop[asdfghjkl;xcvbnm,',
            'dvorak': "',.pyfgcrlaoeuidhtns;qjkxbmwvz",
        }
        
        results = {}
        
        # Try shifting right on QWERTY
        qwerty = 'qwertyuiopasdfghjklzxcvbnm'
        shifted_right = 'wertyuiop[asdfghjkl;xcvbnm,.'
        shifted_left = '`qwertyuioasdfghjkzxcvbn'
        
        trans_right = str.maketrans(qwerty + qwerty.upper(), 
                                    shifted_right + shifted_right.upper())
        trans_left = str.maketrans(qwerty + qwerty.upper(),
                                   shifted_left + shifted_left.upper())
        
        try:
            results['keyboard_shift_right'] = text.translate(trans_right)
            results['keyboard_shift_left'] = text.translate(trans_left)
        except:
            pass
        
        return results
    
    @staticmethod
    def numeric_decode_variants(text):
        """Try various numeric interpretations"""
        results = {}
        
        # Extract all numbers
        import re
        numbers = re.findall(r'\d+', text)
        
        if not numbers:
            return results
        
        # Try as ASCII codes
        try:
            ascii_decode = ''.join(chr(int(n)) if 32 <= int(n) <= 126 else '' for n in numbers)
            if ascii_decode:
                results['numeric_as_ascii'] = ascii_decode
        except:
            pass
        
        # Try as letter positions (A=1, B=2, etc.)
        try:
            letter_decode = ''.join(chr(int(n) + 64) if 1 <= int(n) <= 26 else '' for n in numbers)
            if letter_decode:
                results['numeric_as_letters'] = letter_decode
        except:
            pass
        
        # Try as hex pairs
        if all(int(n) <= 255 for n in numbers):
            try:
                hex_decode = ''.join(chr(int(n)) for n in numbers if 32 <= int(n) <= 126)
                if hex_decode:
                    results['numeric_as_bytes'] = hex_decode
            except:
                pass
        
        return results

    @staticmethod
    def check_anagram(text, min_word_length=3):
        """Check if text contains valid anagram of common words"""
        # Simple word list for checking
        common_words = TextValidator.COMMON_WORDS
        
        text_lower = ''.join(c.lower() for c in text if c.isalpha())
        text_sorted = ''.join(sorted(text_lower))
        
        # Check against common words
        matches = []
        for word in common_words:
            if len(word) >= min_word_length:
                word_sorted = ''.join(sorted(word))
                if word_sorted == text_sorted:
                    matches.append(word)
        
        return matches if matches else None
    
    @staticmethod
    def find_hidden_words(text, min_length=3):
        """Find hidden words by taking every Nth character"""
        results = {}
        
        # Try different step sizes
        for step in range(2, min(len(text) // 2, 10)):
            for offset in range(step):
                hidden = text[offset::step]
                hidden_alpha = ''.join(c for c in hidden if c.isalpha())
                
                if len(hidden_alpha) >= min_length:
                    # Check if it contains common words
                    hidden_lower = hidden_alpha.lower()
                    word_count = sum(1 for word in TextValidator.COMMON_WORDS 
                                   if word in hidden_lower)
                    
                    if word_count > 0:
                        key = f"every_{step}_offset_{offset}"
                        results[key] = hidden_alpha
        
        return results if results else None
    
    @staticmethod
    def circular_shift_left(text, n):
        """Rotate string left by n positions"""
        if not text or n == 0:
            return text
        n = n % len(text)  # Handle n > len(text)
        return text[n:] + text[:n]
    
    @staticmethod
    def circular_shift_right(text, n):
        """Rotate string right by n positions"""
        if not text or n == 0:
            return text
        n = n % len(text)
        return text[-n:] + text[:-n]
    
    @staticmethod
    def all_circular_shifts(text):
        """Generate all circular rotations of text"""
        results = {}
        for i in range(1, len(text)):
            results[i] = Transformers.circular_shift_left(text, i)
        return results
    
    @staticmethod
    def letters_only(text):
        """Extract only letters, removing all other characters"""
        return ''.join(c for c in text if c.isalpha())
    
    @staticmethod
    def letters_only_preserve_case(text):
        """Extract only letters, preserving original case"""
        return ''.join(c for c in text if c.isalpha())
    
    @staticmethod
    def letters_only_spaces(text):
        """Extract only letters and spaces"""
        return ''.join(c for c in text if c.isalpha() or c.isspace())
    
    @staticmethod
    def alphanumeric_only(text):
        """Extract only letters and numbers"""
        return ''.join(c for c in text if c.isalnum())
    
    @staticmethod
    def consonants_only(text):
        """Extract only consonants"""
        vowels = 'aeiouAEIOU'
        return ''.join(c for c in text if c.isalpha() and c not in vowels)
    
    @staticmethod
    def vowels_only(text):
        """Extract only vowels"""
        vowels = 'aeiouAEIOU'
        return ''.join(c for c in text if c in vowels)
    
    @staticmethod
    def running_key_cipher(text, key):
        """Running key cipher (like Vigenere but with a long text key)"""
        # Simplified version - treat like Vigenere with repeating key
        return Transformers.vigenere_decrypt(text, key)
    
    @staticmethod
    def nihilist_cipher_decode(text, key="KEY"):
        """Nihilist cipher decoder (Polybius square with numeric addition)"""
        try:
            # Create Polybius square
            alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J omitted
            square = {}
            for i, char in enumerate(alphabet):
                row = (i // 5) + 1
                col = (i % 5) + 1
                square[char] = row * 10 + col
            
            # Encode key
            key = key.upper().replace('J', 'I')
            key_values = [square.get(c, 0) for c in key if c in square]
            
            # Try to decode (reverse operation)
            # This is simplified - full Nihilist is more complex
            result = []
            numbers = [int(x) for x in text.split() if x.isdigit()]
            
            for i, num in enumerate(numbers):
                key_val = key_values[i % len(key_values)] if key_values else 0
                decoded_val = num - key_val
                
                # Convert back to letter
                if 11 <= decoded_val <= 55:
                    row = decoded_val // 10
                    col = decoded_val % 10
                    if 1 <= row <= 5 and 1 <= col <= 5:
                        idx = (row - 1) * 5 + (col - 1)
                        if idx < len(alphabet):
                            result.append(alphabet[idx])
            
            return ''.join(result)
        except Exception:
            return None
    
    @staticmethod
    def four_square_cipher_decode(text, key1="EXAMPLE", key2="KEYWORD"):
        """Four-square cipher (uses 4 Polybius squares)"""
        # Simplified implementation
        try:
            # This is a complex cipher - simplified version
            return text  # Placeholder
        except Exception:
            return None
    
    @staticmethod
    def straddle_checkerboard_decode(text):
        """Straddle checkerboard cipher"""
        # Simplified implementation
        try:
            return text  # Placeholder
        except Exception:
            return None
    
    @staticmethod
    def homophonic_substitution_decode(text):
        """Homophonic substitution (multiple cipher symbols per plaintext letter)"""
        # This requires specific mapping - placeholder
        return text
    
    @staticmethod
    def book_cipher_decode(text, book_text=""):
        """Book cipher (uses word positions from a book)"""
        # Requires book reference - placeholder
        return text
    
    @staticmethod
    def fractionated_morse_decode(text):
        """Fractionated morse cipher"""
        try:
            # Decode from groups of 3
            morse_to_frac = {
                '...': 'E', '..-': 'T', '..|': 'I',
                '.|.': 'A', '.||': 'N', '|..': 'S',
                # Simplified mapping
            }
            result = []
            for i in range(0, len(text), 3):
                group = text[i:i+3]
                if group in morse_to_frac:
                    result.append(morse_to_frac[group])
            return ''.join(result) if result else None
        except Exception:
            return None
    
    @staticmethod
    def trifid_cipher_decode(text, key="KEYWORD"):
        """Trifid cipher (3D fractionation)"""
        # Complex cipher - simplified placeholder
        try:
            return text  # Would need full implementation
        except Exception:
            return None
    
    @staticmethod
    def double_transposition_decode(text, key1, key2):
        """Double transposition (two columnar transpositions)"""
        try:
            # First transposition
            intermediate = Transformers.columnar_transposition_decode(text, key1)
            # Second transposition
            result = Transformers.columnar_transposition_decode(intermediate, key2)
            return result
        except Exception:
            return None
    
    @staticmethod
    def keyboard_shift(text, shift=1):
        """Keyboard shift cipher (QWERTY adjacent keys)"""
        qwerty_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]
        
        result = []
        for char in text.lower():
            shifted = char
            for row in qwerty_rows:
                if char in row:
                    idx = row.index(char)
                    new_idx = (idx + shift) % len(row)
                    shifted = row[new_idx]
                    break
            
            # Preserve case
            if text[result.__len__()].isupper() if result.__len__() < len(text) else False:
                shifted = shifted.upper()
            result.append(shifted)
        
        return ''.join(result)
    
    @staticmethod
    def phone_keypad_decode(text):
        """Decode phone keypad cipher (T9/multi-tap)"""
        # Phone keypad mapping
        keypad = {
            '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
            '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ'
        }
        
        try:
            # Simple version: each group of same digit = letter
            result = []
            i = 0
            while i < len(text):
                if text[i] in keypad:
                    digit = text[i]
                    count = 1
                    while i + count < len(text) and text[i + count] == digit:
                        count += 1
                    
                    # Get letter from keypad
                    letters = keypad[digit]
                    letter_idx = (count - 1) % len(letters)
                    result.append(letters[letter_idx])
                    i += count
                else:
                    result.append(text[i])
                    i += 1
            
            return ''.join(result)
        except Exception:
            return None
    
    @staticmethod
    def case_flip(text):
        """Flip the case of all letters"""
        return text.swapcase()
    
    @staticmethod
    def alternate_case_decode(text):
        """Try decoding alternate case patterns"""
        # Try lowercase
        lower = text.lower()
        # Try uppercase  
        upper = text.upper()
        # Try swapcase
        swapped = text.swapcase()
        
        return {
            'lower': lower,
            'upper': upper,
            'swapped': swapped
        }
    
    @staticmethod
    def l33t_decode(text):
        """Decode leetspeak/1337 (comprehensive)"""
        leet_map = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '9': 'g',
            '@': 'a', '$': 's', '!': 'i', '|': 'l', '€': 'e'
        }
        
        result = []
        for char in text:
            result.append(leet_map.get(char, char))
        
        return ''.join(result)
    
    @staticmethod
    def extract_flag_formats(text):
        """Extract all flag-like patterns from text"""
        import re
        flags = []
        
        for pattern in [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}',
            r'\w{3,10}\{[^}]{10,}\}'  # Generic format
        ]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    @staticmethod
    def split_alternating(text):
        """Split into alternating characters (odd/even positions)"""
        odd = ''.join(text[i] for i in range(0, len(text), 2))
        even = ''.join(text[i] for i in range(1, len(text), 2))
        return {'odd': odd, 'even': even}
    
    @staticmethod
    def split_by_length(text, parts=2):
        """Split text into N equal parts"""
        chunk_size = len(text) // parts
        chunks = []
        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size if i < parts - 1 else len(text)
            chunks.append(text[start:end])
        return chunks
    
    @staticmethod
    def interleave_strings(str1, str2):
        """Interleave two strings character by character"""
        result = []
        max_len = max(len(str1), len(str2))
        for i in range(max_len):
            if i < len(str1):
                result.append(str1[i])
            if i < len(str2):
                result.append(str2[i])
        return ''.join(result)
    
    @staticmethod
    def deinterleave_string(text):
        """Split interleaved string back into two strings"""
        return Transformers.split_alternating(text)
    
    @staticmethod
    def extract_by_case(text):
        """Extract uppercase and lowercase separately"""
        upper = ''.join(c for c in text if c.isupper())
        lower = ''.join(c for c in text if c.islower())
        return {'upper': upper, 'lower': lower}
    
    @staticmethod
    def extract_by_type(text):
        """Extract different character types"""
        return {
            'letters': ''.join(c for c in text if c.isalpha()),
            'digits': ''.join(c for c in text if c.isdigit()),
            'special': ''.join(c for c in text if not c.isalnum()),
            'alphanum': ''.join(c for c in text if c.isalnum())
        }
    
    @staticmethod
    def zigzag_read(text, rows=3):
        """Read text in zigzag pattern"""
        if rows <= 1 or not text:
            return text
        
        # Create rows
        row_strings = [''] * rows
        current_row = 0
        going_down = False
        
        for char in text:
            row_strings[current_row] += char
            if current_row == 0 or current_row == rows - 1:
                going_down = not going_down
            current_row += 1 if going_down else -1
        
        return ''.join(row_strings)
    
    @staticmethod
    def reverse_words(text):
        """Reverse order of words"""
        words = text.split()
        return ' '.join(reversed(words))
    
    @staticmethod
    def reverse_each_word(text):
        """Reverse each word individually"""
        words = text.split()
        return ' '.join(word[::-1] for word in words)
    
    @staticmethod
    def transpose_grid(text, cols=None):
        """Transpose text as a grid"""
        if cols is None:
            cols = int(len(text) ** 0.5)
        
        if cols == 0:
            return text
        
        rows = (len(text) + cols - 1) // cols
        grid = [[''] * cols for _ in range(rows)]
        
        # Fill grid
        for i, char in enumerate(text):
            row = i // cols
            col = i % cols
            grid[row][col] = char
        
        # Transpose and read
        result = []
        for col in range(cols):
            for row in range(rows):
                if grid[row][col]:
                    result.append(grid[row][col])
        
        return ''.join(result)
    
    @staticmethod
    def xor_with_key(text, key):
        """XOR text with repeating key"""
        if isinstance(text, str):
            text = text.encode('latin-1')
        if isinstance(key, str):
            key = key.encode('latin-1')
        
        result = []
        for i, byte in enumerate(text):
            result.append(byte ^ key[i % len(key)])
        
        return bytes(result).decode('latin-1', errors='ignore')
    
    @staticmethod
    def rolling_xor(text):
        """XOR each byte with previous byte"""
        if isinstance(text, str):
            text = text.encode('latin-1')
        
        result = [text[0]]
        for i in range(1, len(text)):
            result.append(text[i] ^ text[i-1])
        
        return bytes(result).decode('latin-1', errors='ignore')


# ============================================================================
# ENCODINGS - Base64, hex, URL encoding, etc.
# ============================================================================

    @staticmethod
    def keyboard_shift_right(text):
        """Shift characters right on QWERTY keyboard"""
        keyboard = {
            'q': 'w', 'w': 'e', 'e': 'r', 'r': 't', 't': 'y', 'y': 'u', 'u': 'i', 'i': 'o', 'o': 'p', 'p': 'q',
            'a': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h', 'h': 'j', 'j': 'k', 'k': 'l', 'l': 'a',
            'z': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n', 'n': 'm', 'm': 'z',
            '1': '2', '2': '3', '3': '4', '4': '5', '5': '6', '6': '7', '7': '8', '8': '9', '9': '0', '0': '1'
        }
        result = []
        for char in text:
            lower = char.lower()
            if lower in keyboard:
                shifted = keyboard[lower]
                result.append(shifted.upper() if char.isupper() else shifted)
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def keyboard_shift_left(text):
        """Shift characters left on QWERTY keyboard"""
        keyboard = {
            'w': 'q', 'e': 'w', 'r': 'e', 't': 'r', 'y': 't', 'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o', 'q': 'p',
            's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g', 'j': 'h', 'k': 'j', 'l': 'k', 'a': 'l',
            'x': 'z', 'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b', 'm': 'n', 'z': 'm',
            '2': '1', '3': '2', '4': '3', '5': '4', '6': '5', '7': '6', '8': '7', '9': '8', '0': '9', '1': '0'
        }
        result = []
        for char in text:
            lower = char.lower()
            if lower in keyboard:
                shifted = keyboard[lower]
                result.append(shifted.upper() if char.isupper() else shifted)
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def letter_value_cipher(text):
        """Decode A=1, B=2... Z=26 cipher"""
        try:
            parts = re.split(r'[,\s\-_]+', text)
            result = []
            for part in parts:
                if part.isdigit():
                    num = int(part)
                    if 1 <= num <= 26:
                        result.append(chr(ord('A') + num - 1))
            return ''.join(result)
        except Exception:
            return text
    
    @staticmethod
    def phone_t9_decode(text):
        """Decode T9 phone keypad cipher (222=C, 33=E, etc.)"""
        keypad = {
            '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
            '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ', '0': ' '
        }
        result = []
        parts = text.split(' ')
        for part in parts:
            if part and part[0] in keypad:
                digit = part[0]
                count = len(part)
                letters = keypad[digit]
                if count <= len(letters):
                    result.append(letters[count - 1])
        return ''.join(result)
    
    @staticmethod
    def adfgvx_simple_decrypt(text):
        """Simple ADFGVX decrypt (no transposition key)"""
        key = 'ADFGVX'
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        reverse_grid = {}
        for i, char in enumerate(alphabet[:36]):
            row = key[i // 6]
            col = key[i % 6]
            reverse_grid[row + col] = char
        result = []
        for i in range(0, len(text) - 1, 2):
            pair = text[i:i+2].upper()
            if pair in reverse_grid:
                result.append(reverse_grid[pair])
        return ''.join(result)
    
    @staticmethod
    def digraph_substitution(text):
        """Try common digraph substitutions (TH->X, etc.)"""
        digraphs = {
            'TH': 'X', 'HE': 'Y', 'IN': 'Z', 'ER': 'Q', 'AN': 'W',
            'RE': 'E', 'ON': 'R', 'AT': 'T', 'EN': 'A', 'ND': 'S'
        }
        result = text
        for dig, sub in digraphs.items():
            result = result.replace(dig, sub)
        return result
    
    @staticmethod
    def fractional_morse(text):
        """Decode Fractionated Morse (already exists but adding wrapper)"""
        try:
            # Simplified version - just try to decode as morse with X separators
            parts = text.split('X')
            result = []
            morse_rev = {
                '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
                '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
                '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
                '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                '-.--': 'Y', '--..': 'Z'
            }
            for part in parts:
                if part in morse_rev:
                    result.append(morse_rev[part])
            return ''.join(result)
        except Exception:
            return text


class Encodings:
    """Methods for encoding and decoding data"""
    
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    
    @staticmethod
    def to_base64(text):
        """Encode text to base64"""
        if isinstance(text, str):
            text = text.encode()
        return base64.b64encode(text).decode()
    
    @staticmethod
    def from_base64(encoded):
        """Decode base64 to text"""
        try:
            # Add padding if needed
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            return base64.b64decode(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_hex(text):
        """Encode text to hexadecimal"""
        if isinstance(text, str):
            text = text.encode()
        return text.hex()
    
    @staticmethod
    def from_hex(hex_string):
        """Decode hexadecimal to text"""
        try:
            hex_string = hex_string.replace(' ', '').replace('0x', '').replace('\\x', '')
            hex_string = hex_string.replace(':', '').replace('-', '')
            return bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_binary(text):
        """Convert text to binary representation"""
        if isinstance(text, str):
            text = text.encode()
        return ' '.join(format(byte, '08b') for byte in text)
    
    @staticmethod
    def from_binary(binary_string):
        """Convert binary representation to text"""
        try:
            binary_string = binary_string.replace(' ', '').replace('0b', '')
            bytes_list = [int(binary_string[i:i+8], 2) 
                         for i in range(0, len(binary_string), 8)]
            return bytes(bytes_list).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_octal(text):
        """Convert text to octal"""
        if isinstance(text, str):
            text = text.encode()
        return ' '.join(oct(byte)[2:] for byte in text)
    
    @staticmethod
    def from_octal(octal_string):
        """Convert octal to text"""
        try:
            octal_string = octal_string.replace('\\', '').replace('0o', '')
            octals = octal_string.split()
            return bytes([int(o, 8) for o in octals]).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_url_encoding(text):
        """URL encode text"""
        return quote(text)
    
    @staticmethod
    def from_url_encoding(encoded):
        """URL decode text"""
        try:
            return unquote(encoded)
        except Exception:
            return None
    
    @staticmethod
    def to_ascii_values(text):
        """Convert text to ASCII values"""
        return [ord(char) for char in text]
    
    @staticmethod
    def from_ascii_values(values):
        """Convert ASCII values to text"""
        try:
            return ''.join(chr(val) for val in values)
        except Exception:
            return None
    
    @staticmethod
    def to_base32(text):
        """Encode text to base32"""
        if isinstance(text, str):
            text = text.encode()
        return base64.b32encode(text).decode()
    
    @staticmethod
    def from_base32(encoded):
        """Decode base32 to text"""
        try:
            missing_padding = len(encoded) % 8
            if missing_padding:
                encoded += '=' * (8 - missing_padding)
            return base64.b32decode(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_base85(text):
        """Encode text to base85"""
        if isinstance(text, str):
            text = text.encode()
        return base64.b85encode(text).decode()
    
    @staticmethod
    def from_base85(encoded):
        """Decode base85 to text"""
        try:
            return base64.b85decode(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_base16(text):
        """Encode text to base16"""
        if isinstance(text, str):
            text = text.encode()
        return base64.b16encode(text).decode()
    
    @staticmethod
    def from_base16(encoded):
        """Decode base16 to text"""
        try:
            return base64.b16decode(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_morse(text):
        """Convert text to Morse code"""
        result = []
        for char in text.upper():
            if char in Encodings.MORSE_CODE:
                result.append(Encodings.MORSE_CODE[char])
            else:
                result.append(char)
        return ' '.join(result)
    
    @staticmethod
    def from_morse(morse):
        """Decode Morse code to text"""
        try:
            reverse_morse = {v: k for k, v in Encodings.MORSE_CODE.items()}
            words = morse.split(' / ')
            result = []
            for word in words:
                letters = word.split()
                for letter in letters:
                    result.append(reverse_morse.get(letter, '?'))
                result.append(' ')
            return ''.join(result).strip()
        except Exception:
            return None
    
    @staticmethod
    def to_rot13(text):
        """ROT13 encoding"""
        return codecs.encode(text, 'rot13')
    
    @staticmethod
    def from_rot13(text):
        """ROT13 decoding (same as encoding)"""
        return codecs.decode(text, 'rot13')
    
    @staticmethod
    def to_uuencode(text):
        """UUencode encoding"""
        if isinstance(text, str):
            text = text.encode()
        try:
            import uu
            from io import BytesIO
            input_buf = BytesIO(text)
            output_buf = BytesIO()
            uu.encode(input_buf, output_buf, 'data')
            return output_buf.getvalue().decode()
        except Exception:
            return None
    
    @staticmethod
    def from_uuencode(encoded):
        """UUencode decoding"""
        try:
            import uu
            from io import BytesIO
            input_buf = BytesIO(encoded.encode())
            output_buf = BytesIO()
            uu.decode(input_buf, output_buf)
            return output_buf.getvalue().decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_quoted_printable(text):
        """Quoted-printable encoding"""
        if isinstance(text, str):
            text = text.encode()
        import quopri
        return quopri.encodestring(text).decode()
    
    @staticmethod
    def from_quoted_printable(encoded):
        """Quoted-printable decoding"""
        try:
            import quopri
            if isinstance(encoded, str):
                encoded = encoded.encode()
            return quopri.decodestring(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_punycode(text):
        """Punycode encoding"""
        try:
            return text.encode('punycode').decode()
        except Exception:
            return None
    
    @staticmethod
    def from_punycode(encoded):
        """Punycode decoding"""
        try:
            return encoded.encode().decode('punycode')
        except Exception:
            return None
    
    @staticmethod
    def from_decimal(decimal_string):
        """Convert decimal numbers to text"""
        try:
            numbers = re.findall(r'\d+', decimal_string)
            return ''.join(chr(int(n)) for n in numbers if int(n) < 256)
        except Exception:
            return None
    
    @staticmethod
    def from_html_entities(text):
        """Decode HTML entities"""
        import html
        return html.unescape(text)
    
    @staticmethod
    def to_html_entities(text):
        """Encode to HTML entities"""
        import html
        return html.escape(text)
    
    @staticmethod
    def from_unicode_escape(text):
        """Decode unicode escape sequences"""
        try:
            return text.encode().decode('unicode-escape')
        except Exception:
            return None
    
    @staticmethod
    def from_base58(encoded):
        """Decode base58 (Bitcoin style)"""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        try:
            decoded = 0
            for char in encoded:
                decoded = decoded * 58 + alphabet.index(char)
            
            result = []
            while decoded > 0:
                result.append(decoded % 256)
                decoded //= 256
            
            return bytes(reversed(result)).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base62(encoded):
        """Decode base62"""
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        try:
            decoded = 0
            for char in encoded:
                decoded = decoded * 62 + alphabet.index(char)
            
            result = []
            while decoded > 0:
                result.append(decoded % 256)
                decoded //= 256
            
            return bytes(reversed(result)).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base91(encoded):
        """Decode base91"""
        base91_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        try:
            v = -1
            b = 0
            n = 0
            output = []
            for char in encoded:
                c = base91_alphabet.index(char)
                if v < 0:
                    v = c
                else:
                    v += c * 91
                    if v & 8191 > 88:
                        b |= (v & 8191) << n
                        n += 13
                    else:
                        b |= (v & 16383) << n
                        n += 14
                    while True:
                        output.append(b & 255)
                        b >>= 8
                        n -= 8
                        if n <= 7:
                            break
                    v = -1
            if v >= 0:
                output.append((b | v << n) & 255)
            return bytes(output).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base36(encoded):
        """Decode base36 (0-9, A-Z)"""
        try:
            # Base36 is typically used for numbers
            num = int(encoded, 36)
            # Convert to bytes
            result = []
            while num > 0:
                result.append(num % 256)
                num //= 256
            return bytes(reversed(result)).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_base36(text):
        """Encode to base36"""
        if isinstance(text, str):
            text = text.encode()
        num = int.from_bytes(text, 'big')
        if num == 0:
            return '0'
        
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        result = []
        while num > 0:
            result.append(alphabet[num % 36])
            num //= 36
        return ''.join(reversed(result))
    
    @staticmethod
    def from_base45(encoded):
        """Decode base45 (used in EU COVID certificates)"""
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
        try:
            result = []
            i = 0
            while i < len(encoded):
                if i + 2 < len(encoded):
                    # Process 3 characters
                    c = alphabet.index(encoded[i])
                    d = alphabet.index(encoded[i+1])
                    e = alphabet.index(encoded[i+2])
                    
                    value = c + d * 45 + e * 45 * 45
                    result.append(value // 256)
                    result.append(value % 256)
                    i += 3
                elif i + 1 < len(encoded):
                    # Process 2 characters
                    c = alphabet.index(encoded[i])
                    d = alphabet.index(encoded[i+1])
                    value = c + d * 45
                    result.append(value)
                    i += 2
                else:
                    i += 1
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_base45(text):
        """Encode to base45"""
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
        if isinstance(text, str):
            text = text.encode()
        
        result = []
        i = 0
        while i < len(text):
            if i + 1 < len(text):
                # Process 2 bytes
                value = text[i] * 256 + text[i+1]
                
                c = value % 45
                value //= 45
                d = value % 45
                value //= 45
                e = value % 45
                
                result.append(alphabet[c])
                result.append(alphabet[d])
                result.append(alphabet[e])
                i += 2
            else:
                # Process 1 byte
                value = text[i]
                c = value % 45
                d = value // 45
                result.append(alphabet[c])
                result.append(alphabet[d])
                i += 1
        
        return ''.join(result)
    
    @staticmethod
    def from_ascii85(encoded):
        """Decode ASCII85 (similar to base85 but different)"""
        try:
            # Remove whitespace
            encoded = ''.join(encoded.split())
            
            # Handle special case 'z' = 00000000
            encoded = encoded.replace('z', '!!!!!')
            
            result = []
            for i in range(0, len(encoded), 5):
                chunk = encoded[i:i+5]
                if len(chunk) < 5:
                    chunk = chunk + 'u' * (5 - len(chunk))
                
                value = 0
                for c in chunk:
                    value = value * 85 + (ord(c) - 33)
                
                # Convert to 4 bytes
                for j in range(3, -1, -1):
                    result.append((value >> (j * 8)) & 0xFF)
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_z85(encoded):
        """Decode Z85 (ZeroMQ base85)"""
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
        try:
            result = []
            for i in range(0, len(encoded), 5):
                chunk = encoded[i:i+5]
                if len(chunk) == 5:
                    value = 0
                    for c in chunk:
                        value = value * 85 + alphabet.index(c)
                    
                    for j in range(3, -1, -1):
                        result.append((value >> (j * 8)) & 0xFF)
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base32hex(encoded):
        """Decode base32hex (extended hex alphabet variant)"""
        try:
            # base32hex uses 0-9 A-V instead of A-Z 2-7
            import base64
            missing_padding = len(encoded) % 8
            if missing_padding:
                encoded += '=' * (8 - missing_padding)
            return base64.b32hexdecode(encoded).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_crockford_base32(encoded):
        """Decode Crockford base32 (alternative base32 encoding)"""
        # Crockford alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
        alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
        try:
            encoded = encoded.upper().replace('O', '0').replace('I', '1').replace('L', '1')
            
            num = 0
            for c in encoded:
                if c in alphabet:
                    num = num * 32 + alphabet.index(c)
            
            result = []
            while num > 0:
                result.append(num % 256)
                num //= 256
            
            return bytes(reversed(result)).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_bubble_babble(encoded):
        """Decode Bubble Babble (pronounceable encoding)"""
        vowels = 'aeiouy'
        consonants = 'bcdfghklmnprstvzx'
        
        try:
            if not encoded.startswith('x') or not encoded.endswith('x'):
                return None
            
            encoded = encoded[1:-1]  # Remove x...x wrapping
            result = []
            checksum = 1
            
            # Process tuples of 6 characters
            for i in range(0, len(encoded), 6):
                if i + 5 < len(encoded):
                    # Full tuple
                    v1, c1, v2, c2, v3, c3 = encoded[i:i+6]
                    
                    if v1 in vowels and c1 in consonants and v2 in vowels and \
                       c2 in consonants and v3 in vowels and c3 in consonants:
                        
                        byte1 = ((vowels.index(v1) - checksum) % 6) * 16 + consonants.index(c1)
                        byte2 = vowels.index(v2) * 16 + consonants.index(c2)
                        
                        result.append(byte1)
                        result.append(byte2)
                        
                        checksum = (checksum * 5 + byte1 * 7 + byte2) % 36
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_tap_code(encoded):
        """Decode tap code (prison knock code)"""
        # 5x5 grid, K omitted (C used for K)
        grid = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'J'],
            ['L', 'M', 'N', 'O', 'P'],
            ['Q', 'R', 'S', 'T', 'U'],
            ['V', 'W', 'X', 'Y', 'Z']
        ]
        
        try:
            # Parse taps (e.g., "2 3" or ".. ...")
            pairs = []
            parts = encoded.strip().split()
            
            for i in range(0, len(parts), 2):
                if i + 1 < len(parts):
                    row_taps = parts[i]
                    col_taps = parts[i+1]
                    
                    # Count taps (dots or numbers)
                    if '.' in row_taps:
                        row = row_taps.count('.')
                        col = col_taps.count('.')
                    else:
                        row = int(row_taps)
                        col = int(col_taps)
                    
                    if 1 <= row <= 5 and 1 <= col <= 5:
                        pairs.append(grid[row-1][col-1])
            
            return ''.join(pairs)
        except Exception:
            return None
    
    @staticmethod
    def from_gray_code(encoded):
        """Decode Gray code"""
        try:
            # Remove spaces
            binary_str = encoded.replace(' ', '')
            
            # Process in 8-bit chunks
            result = []
            for i in range(0, len(binary_str), 8):
                chunk = binary_str[i:i+8]
                if len(chunk) == 8:
                    gray = int(chunk, 2)
                    # Convert Gray to binary
                    binary = gray
                    while gray > 0:
                        gray >>= 1
                        binary ^= gray
                    result.append(binary)
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def to_gray_code(text):
        """Encode to Gray code"""
        if isinstance(text, str):
            text = text.encode()
        
        result = []
        for byte in text:
            # Convert to Gray code
            gray = byte ^ (byte >> 1)
            result.append(format(gray, '08b'))
        
        return ' '.join(result)
    
    @staticmethod
    def from_bit_reversed(encoded):
        """Decode bit-reversed text"""
        try:
            if isinstance(encoded, str):
                encoded = encoded.encode()
            
            result = []
            for byte in encoded:
                # Reverse bits
                reversed_byte = int('{:08b}'.format(byte)[::-1], 2)
                result.append(reversed_byte)
            
            return bytes(result).decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base2048(encoded):
        """Decode base2048 (uses Unicode range)"""
        # Simplified base2048 - just a placeholder
        # Real base2048 uses specific Unicode ranges
        try:
            # This is a simplified version
            return encoded  # Would need proper implementation
        except Exception:
            return None
    
    @staticmethod
    def from_base122(encoded):
        """Decode base122 (7-bit efficient encoding)"""
        try:
            # Simplified base122
            return encoded  # Would need proper implementation
        except Exception:
            return None
    
    @staticmethod
    def from_nato_phonetic(text):
        """Decode NATO phonetic alphabet"""
        nato = {
            'ALPHA': 'A', 'BRAVO': 'B', 'CHARLIE': 'C', 'DELTA': 'D',
            'ECHO': 'E', 'FOXTROT': 'F', 'GOLF': 'G', 'HOTEL': 'H',
            'INDIA': 'I', 'JULIET': 'J', 'KILO': 'K', 'LIMA': 'L',
            'MIKE': 'M', 'NOVEMBER': 'N', 'OSCAR': 'O', 'PAPA': 'P',
            'QUEBEC': 'Q', 'ROMEO': 'R', 'SIERRA': 'S', 'TANGO': 'T',
            'UNIFORM': 'U', 'VICTOR': 'V', 'WHISKEY': 'W', 'XRAY': 'X',
            'YANKEE': 'Y', 'ZULU': 'Z'
        }
        
        try:
            words = text.upper().split()
            result = []
            for word in words:
                if word in nato:
                    result.append(nato[word])
            return ''.join(result) if result else None
        except Exception:
            return None
    
    @staticmethod
    def to_nato_phonetic(text):
        """Encode to NATO phonetic alphabet"""
        nato = {
            'A': 'ALPHA', 'B': 'BRAVO', 'C': 'CHARLIE', 'D': 'DELTA',
            'E': 'ECHO', 'F': 'FOXTROT', 'G': 'GOLF', 'H': 'HOTEL',
            'I': 'INDIA', 'J': 'JULIET', 'K': 'KILO', 'L': 'LIMA',
            'M': 'MIKE', 'N': 'NOVEMBER', 'O': 'OSCAR', 'P': 'PAPA',
            'Q': 'QUEBEC', 'R': 'ROMEO', 'S': 'SIERRA', 'T': 'TANGO',
            'U': 'UNIFORM', 'V': 'VICTOR', 'W': 'WHISKEY', 'X': 'XRAY',
            'Y': 'YANKEE', 'Z': 'ZULU'
        }
        
        result = []
        for char in text.upper():
            if char in nato:
                result.append(nato[char])
        return ' '.join(result)
    
    @staticmethod
    def from_reverse_alphabet(text):
        """Decode reverse alphabet (A=Z, B=Y, etc.) - same as Atbash"""
        # This is the same as Atbash
        result = []
        for char in text:
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            elif char.islower():
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def from_base41(encoded):
        """Decode base41 (compact encoding)"""
        try:
            # Simplified placeholder
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_ascii_armor(text):
        """Decode ASCII armored text (like PGP)"""
        try:
            # Extract content between BEGIN/END markers
            import re
            match = re.search(r'-----BEGIN.*?-----\s*(.*?)\s*-----END', text, re.DOTALL)
            if match:
                content = match.group(1).replace('\n', '').replace(' ', '')
                # Try base64 decode
                return Encodings.from_base64(content)
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_yenc(encoded):
        """Decode yEnc encoding"""
        try:
            result = []
            for char in encoded:
                val = ord(char) - 42
                if val < 0:
                    val += 256
                result.append(chr(val))
            return ''.join(result)
        except Exception:
            return None
    
    @staticmethod
    def from_xxencoding(encoded):
        """Decode xxencoding"""
        try:
            # Similar to uuencode but different alphabet
            # Simplified implementation
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_quoted_printable_q(encoded):
        """Decode Q-encoding (variant of quoted-printable)"""
        try:
            # Replace underscores with spaces
            decoded = encoded.replace('_', ' ')
            # Decode hex sequences
            import re
            def replace_hex(match):
                return chr(int(match.group(1), 16))
            decoded = re.sub(r'=([0-9A-Fa-f]{2})', replace_hex, decoded)
            return decoded
        except Exception:
            return None
    
    @staticmethod
    def from_percent_encoding(encoded):
        """Decode percent encoding (like URL but more general)"""
        try:
            import re
            def replace_percent(match):
                return chr(int(match.group(1), 16))
            decoded = re.sub(r'%([0-9A-Fa-f]{2})', replace_percent, encoded)
            return decoded
        except Exception:
            return None
    
    @staticmethod
    def from_base64_urlsafe(encoded):
        """Decode URL-safe base64 (- and _ instead of + and /)"""
        try:
            import base64
            # Add padding if needed
            padding = 4 - (len(encoded) % 4)
            if padding and padding != 4:
                encoded += '=' * padding
            decoded = base64.urlsafe_b64decode(encoded)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base64_reversed(encoded):
        """Decode reversed base64 (common CTF trick)"""
        try:
            reversed_text = encoded[::-1]
            return Encodings.from_base64(reversed_text)
        except Exception:
            return None
    
    @staticmethod
    def from_hex_reversed(encoded):
        """Decode reversed hex"""
        try:
            reversed_text = encoded[::-1]
            return Encodings.from_hex(reversed_text)
        except Exception:
            return None
    
    @staticmethod
    def from_python_string_literal(encoded):
        """Decode Python string literal with \\x notation"""
        try:
            # Handle \x notation
            import re
            def replace_hex(match):
                return chr(int(match.group(1), 16))
            decoded = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_hex, encoded)
            # Handle \n, \t, etc
            decoded = decoded.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
            decoded = decoded.replace('\\\\', '\\').replace("\\'", "'").replace('\\"', '"')
            return decoded
        except Exception:
            return None
    
    @staticmethod
    def from_c_string_literal(encoded):
        """Decode C string literal"""
        return Encodings.from_python_string_literal(encoded)
    
    @staticmethod
    def from_base36(encoded):
        """Decode base36 (0-9, A-Z) - treating as single large number"""
        try:
            # Convert base36 string to integer
            num = int(encoded, 36)
            # Convert to hex
            hex_str = hex(num)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            # Convert to bytes
            decoded = bytes.fromhex(hex_str)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base36_chunks(encoded, chunk_size=2):
        """Decode base36 in chunks (each chunk is a byte)"""
        try:
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            decoded_bytes = []
            for chunk in chunks:
                if chunk:
                    val = int(chunk, 36)
                    if val < 256:
                        decoded_bytes.append(val)
            
            if decoded_bytes:
                return bytes(decoded_bytes).decode('utf-8', errors='ignore')
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_custom_base32(encoded, alphabet=None):
        """Decode custom base32 with provided alphabet"""
        if alphabet is None:
            # Use sorted unique characters as alphabet
            alphabet = ''.join(sorted(set(encoded)))
        
        if len(alphabet) != 32:
            return None
        
        try:
            binary = ''
            for char in encoded:
                if char in alphabet:
                    value = alphabet.index(char)
                    binary += format(value, '05b')
            
            # Convert binary to bytes
            result = []
            for i in range(0, len(binary) - (len(binary) % 8), 8):
                byte = binary[i:i+8]
                result.append(int(byte, 2))
            
            decoded = bytes(result)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_base32_z(encoded):
        """Decode z-base-32"""
        try:
            z_alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
            std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(z_alphabet, std_alphabet)
            translated = encoded.lower().translate(trans).upper()
            
            # Try with various padding
            for pad in range(8):
                try:
                    import base64
                    decoded = base64.b32decode(translated + '=' * pad)
                    return decoded.decode('utf-8', errors='ignore')
                except:
                    pass
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_geohash_base32(encoded):
        """Decode geohash base32"""
        try:
            geohash_alphabet = "0123456789bcdefghjkmnpqrstuvwxyz"
            std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(geohash_alphabet, std_alphabet.lower())
            translated = encoded.lower().translate(trans).upper()
            
            # Try with various padding
            for pad in range(8):
                try:
                    import base64
                    decoded = base64.b32decode(translated + '=' * pad)
                    return decoded.decode('utf-8', errors='ignore')
                except:
                    pass
            return None
        except Exception:
            return None
    
    @staticmethod
    def try_as_coordinates(encoded):
        """Try to decode as Polybius square coordinates"""
        try:
            polybius = {
                '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E',
                '21': 'F', '22': 'G', '23': 'H', '24': 'I', '25': 'K',
                '31': 'L', '32': 'M', '33': 'N', '34': 'O', '35': 'P',
                '41': 'Q', '42': 'R', '43': 'S', '44': 'T', '45': 'U',
                '51': 'V', '52': 'W', '53': 'X', '54': 'Y', '55': 'Z'
            }
            
            result = []
            i = 0
            while i < len(encoded) - 1:
                if encoded[i].isdigit() and encoded[i+1].isdigit():
                    pair = encoded[i:i+2]
                    if pair in polybius:
                        result.append(polybius[pair])
                        i += 2
                    else:
                        i += 1
                else:
                    i += 1
            
            if result:
                return ''.join(result)
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_variable_rot(encoded):
        """Decode variable ROT cipher (numbers indicate ROT amount for following letters)"""
        try:
            result = []
            current_rot = 0
            for char in encoded:
                if char.isdigit():
                    current_rot = int(char)
                elif char.isalpha():
                    if char.isupper():
                        rotated = chr((ord(char) - ord('A') + current_rot) % 26 + ord('A'))
                    else:
                        rotated = chr((ord(char) - ord('a') + current_rot) % 26 + ord('a'))
                    result.append(rotated)
                else:
                    result.append(char)
            
            if result:
                return ''.join(result)
            return None
        except Exception:
            return None
    
    @staticmethod
    def analyze_for_patterns(text):
        """Analyze text for repeated patterns (useful for analysis)"""
        try:
            patterns = {}
            for length in [2, 3, 4, 5]:
                seen = {}
                for i in range(len(text) - length + 1):
                    substring = text[i:i+length]
                    seen[substring] = seen.get(substring, 0) + 1
                
                repeated = {k: v for k, v in seen.items() if v > 1}
                if repeated:
                    patterns[length] = dict(sorted(repeated.items(), key=lambda x: x[1], reverse=True)[:5])
            
            return patterns if patterns else None
        except Exception:
            return None
    
    @staticmethod
    def from_xxd_dump(encoded):
        """Decode xxd hex dump format"""
        try:
            import re
            # Extract hex bytes from xxd format
            # Format: 00000000: 4865 6c6c 6f20 576f 726c 6421 0a         Hello World!.
            lines = encoded.split('\n')
            hex_bytes = []
            for line in lines:
                # Extract hex part (between : and ASCII representation)
                match = re.search(r':\s+([0-9a-fA-F\s]+)', line)
                if match:
                    hex_part = match.group(1).replace(' ', '')
                    hex_bytes.append(hex_part)
            
            full_hex = ''.join(hex_bytes)
            if full_hex:
                return bytes.fromhex(full_hex).decode('utf-8', errors='ignore')
            return None
        except Exception:
            return None
        """Decode xxd hex dump format"""
        try:
            import re
            # Extract hex bytes from xxd format
            # Format: 00000000: 4865 6c6c 6f20 576f 726c 6421 0a         Hello World!.
            lines = encoded.split('\n')
            hex_bytes = []
            for line in lines:
                # Extract hex part (between : and ASCII representation)
                match = re.search(r':\s+([0-9a-fA-F\s]+)', line)
                if match:
                    hex_part = match.group(1).replace(' ', '')
                    hex_bytes.append(hex_part)
            
            full_hex = ''.join(hex_bytes)
            if full_hex:
                return bytes.fromhex(full_hex).decode('utf-8', errors='ignore')
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_zlib(data):
        """Decompress zlib compressed data"""
        try:
            import zlib
            # Try as bytes first
            if isinstance(data, str):
                # Try hex
                try:
                    data = bytes.fromhex(data.replace(' ', ''))
                except:
                    # Try base64
                    try:
                        import base64
                        data = base64.b64decode(data)
                    except:
                        data = data.encode('latin-1')
            
            decompressed = zlib.decompress(data)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_gzip(data):
        """Decompress gzip compressed data"""
        try:
            import gzip
            import io
            
            # Try as bytes first
            if isinstance(data, str):
                # Try hex
                try:
                    data = bytes.fromhex(data.replace(' ', ''))
                except:
                    # Try base64
                    try:
                        import base64
                        data = base64.b64decode(data)
                    except:
                        data = data.encode('latin-1')
            
            decompressed = gzip.decompress(data)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_bz2(data):
        """Decompress bz2 compressed data"""
        try:
            import bz2
            
            # Try as bytes first
            if isinstance(data, str):
                # Try hex
                try:
                    data = bytes.fromhex(data.replace(' ', ''))
                except:
                    # Try base64
                    try:
                        import base64
                        data = base64.b64decode(data)
                    except:
                        data = data.encode('latin-1')
            
            decompressed = bz2.decompress(data)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_lzma(data):
        """Decompress LZMA/XZ compressed data"""
        try:
            import lzma
            
            # Try as bytes first
            if isinstance(data, str):
                # Try hex
                try:
                    data = bytes.fromhex(data.replace(' ', ''))
                except:
                    # Try base64
                    try:
                        import base64
                        data = base64.b64decode(data)
                    except:
                        data = data.encode('latin-1')
            
            decompressed = lzma.decompress(data)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def from_deflate(data):
        """Decompress raw deflate data"""
        try:
            import zlib
            
            # Try as bytes first
            if isinstance(data, str):
                # Try hex
                try:
                    data = bytes.fromhex(data.replace(' ', ''))
                except:
                    # Try base64
                    try:
                        import base64
                        data = base64.b64decode(data)
                    except:
                        data = data.encode('latin-1')
            
            # Try raw deflate (negative wbits)
            decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    @staticmethod
    def is_compressed(data):
        """Detect if data is likely compressed"""
        if isinstance(data, str):
            # Try to convert to bytes
            try:
                if data.startswith('1f8b'):  # gzip magic
                    return 'gzip'
                if data.startswith('425a'):  # bz2 magic
                    return 'bz2'
                if data.startswith('fd377a585a00'):  # xz magic
                    return 'xz'
                
                # Try as hex
                try:
                    test_bytes = bytes.fromhex(data[:20].replace(' ', ''))
                    return Encodings.is_compressed(test_bytes)
                except:
                    pass
            except:
                pass
        
        if isinstance(data, bytes):
            # Check magic numbers
            if data[:2] == b'\x1f\x8b':
                return 'gzip'
            if data[:2] == b'BZ':
                return 'bz2'
            if data[:6] == b'\xfd7zXZ\x00':
                return 'xz'
            if data[:2] == b'\x78\x9c' or data[:2] == b'\x78\x01' or data[:2] == b'\x78\xda':
                return 'zlib'
        
        return None
    
    @staticmethod
    def from_netscape_bookmark(encoded):
        """Extract text from Netscape bookmark format"""
        try:
            import re
            # Extract URLs and names
            matches = re.findall(r'HREF="([^"]*)"[^>]*>([^<]*)', encoded)
            return ' '.join([name for url, name in matches]) if matches else None
        except Exception:
            return None

    @staticmethod
    def from_base122(encoded):
        """Base122 decoding (efficient 7-bit encoding)"""
        try:
            result = []
            for char in encoded:
                code = ord(char)
                if code >= 128:
                    result.append(chr(code - 128))
                else:
                    result.append(char)
            return ''.join(result)
        except Exception:
            return None
    
    @staticmethod
    def from_netstring(text):
        """Netstring decoding (length:data,)"""
        try:
            if ':' not in text or not text.endswith(','):
                return None
            length_str, rest = text.split(':', 1)
            length = int(length_str)
            data = rest[:-1]
            if len(data) == length:
                return data
            return None
        except Exception:
            return None
    
    @staticmethod
    def from_c_escape(text):
        """Decode C-style escape sequences"""
        try:
            result = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
            result = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), result)
            result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), result)
            result = result.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
            result = result.replace('\\\\', '\\').replace('\\"', '"')
            return result
        except Exception:
            return None
    
    @staticmethod
    def from_decimal_array(text):
        """Decode array of decimal ASCII values like [72, 101, 108, 108, 111]"""
        try:
            # Remove brackets and parse numbers
            text = text.strip('[](){}')
            numbers = [int(x.strip()) for x in text.split(',') if x.strip().isdigit()]
            return ''.join(chr(n) for n in numbers if 0 <= n <= 1114111)
        except Exception:
            return None
    
    @staticmethod
    def from_ascii_array(text):
        """Decode space/comma separated ASCII decimal values"""
        try:
            parts = re.split(r'[,\s]+', text.strip())
            return ''.join(chr(int(p)) for p in parts if p.isdigit() and 0 <= int(p) <= 127)
        except Exception:
            return None



    @staticmethod
    def detect_custom_base32(text):
        """Detect and decode custom base32 (32 unique characters)"""
        unique_chars = sorted(set(text))
        
        if len(unique_chars) != 32:
            return None
        
        # Use the actual characters as alphabet
        custom_alphabet = ''.join(unique_chars)
        
        # Decode as base32
        binary = ''
        for char in text:
            if char in custom_alphabet:
                value = custom_alphabet.index(char)
                binary += format(value, '05b')
        
        results = {}
        
        # Try without offset
        result_bytes = []
        for i in range(0, len(binary) - (len(binary) % 8), 8):
            byte = binary[i:i+8]
            result_bytes.append(int(byte, 2))
        
        result = bytes(result_bytes)
        if all(32 <= b <= 126 for b in result):
            results['no_offset'] = result.decode('ascii', errors='ignore')
        
        # Try bit offsets 1-7
        for offset in range(1, 8):
            offset_binary = binary[offset:]
            result_bytes = []
            for i in range(0, len(offset_binary) - (len(offset_binary) % 8), 8):
                byte = offset_binary[i:i+8]
                result_bytes.append(int(byte, 2))
            
            result = bytes(result_bytes)
            if all(32 <= b <= 126 for b in result):
                results[f'offset_{offset}'] = result.decode('ascii', errors='ignore')
        
        return results if results else None
    
    @staticmethod
    def chunked_base_decode(text, chunk_size=2, base=36):
        """Decode text as chunks in given base"""
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        
        try:
            decoded_bytes = []
            for chunk in chunks:
                if chunk:
                    val = int(chunk, base)
                    if val < 256:
                        decoded_bytes.append(val)
            
            if decoded_bytes:
                result = bytes(decoded_bytes)
                if all(32 <= b <= 126 for b in result):
                    return result.decode('ascii', errors='ignore')
        except:
            pass
        
        return None


# ============================================================================
# TEXT VALIDATION - Verify if output is valid text
# ============================================================================

class TextValidator:
    """Methods for validating and analyzing text"""
    
    # Common English letter frequencies (in percentages)
    ENGLISH_FREQ = {
        'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
        'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
        'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
        'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
        'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }
    
    # Extended common English words for validation
    COMMON_WORDS = set([
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
        'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
        'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
        'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
        'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go',
        'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
        'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them',
        'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over',
        'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
        'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day',
        'most', 'us', 'is', 'was', 'are', 'been', 'has', 'had', 'were', 'said', 'did',
        'having', 'may', 'should', 'am', 'being', 'been', 'where', 'why', 'how', 'each',
        'which', 'their', 'here', 'more', 'many', 'much', 'very', 'such', 'long', 'own',
        'too', 'can', 'flag', 'ctf', 'crypto', 'key', 'password', 'secret', 'message',
        'code', 'text', 'data', 'word', 'letter', 'number', 'string', 'value', 'result',
        'hello', 'world', 'hi', 'hey', 'yes', 'ok', 'okay', 'please', 'thanks', 'thank',
        'welcome', 'test', 'testing', 'example', 'sample', 'quick', 'brown', 'fox',
        'jumps', 'jumped', 'lazy', 'dog', 'cat', 'man', 'woman', 'men', 'child', 'life',
        'hand', 'part', 'place', 'case', 'week', 'company', 'system', 'program', 'question',
        'government', 'night', 'point', 'home', 'water', 'room', 'mother', 'father',
        'area', 'money', 'story', 'fact', 'month', 'lot', 'right', 'study', 'book', 'eye',
        'job', 'business', 'issue', 'side', 'kind', 'head', 'house', 'service', 'friend',
        'power', 'hour', 'game', 'line', 'end', 'member', 'law', 'car', 'city', 'name',
        'team', 'minute', 'idea', 'kid', 'body', 'information', 'face', 'others', 'level',
        'office', 'door', 'health', 'person', 'art', 'war', 'history', 'party', 'change',
        'morning', 'reason', 'research', 'girl', 'guy', 'moment', 'air', 'teacher',
        'force', 'education', 'find', 'found', 'tell', 'told', 'ask', 'seem', 'feel',
        'try', 'leave', 'call', 'keep', 'let', 'begin', 'help', 'talk', 'turn', 'start',
        'show', 'hear', 'play', 'run', 'move', 'live', 'believe', 'hold', 'bring', 'happen',
        'write', 'provide', 'sit', 'stand', 'lose', 'pay', 'meet', 'include', 'continue',
        'set', 'learn', 'lead', 'understand', 'watch', 'follow', 'stop', 'create', 'speak',
        'read', 'allow', 'add', 'spend', 'grow', 'open', 'walk', 'win', 'offer', 'remember',
        'love', 'consider', 'appear', 'buy', 'wait', 'serve', 'die', 'send', 'expect',
        'build', 'stay', 'fall', 'cut', 'reach', 'kill', 'remain', 'great', 'little',
        'old', 'big', 'high', 'different', 'small', 'large', 'next', 'early', 'young',
        'important', 'few', 'public', 'bad', 'same', 'able', 'last', 'best', 'better',
        'sure', 'free', 'true', 'false', 'real', 'full', 'hard', 'easy', 'strong', 'clear',
        'never', 'always', 'again', 'still', 'down', 'off', 'before', 'through', 'under',
        'around', 'between', 'without', 'against', 'during', 'while', 'every', 'both',
        'those', 'another', 'something', 'nothing', 'everything', 'anything', 'hidden',
        'find', 'found', 'decode', 'decoded', 'encode', 'encoded', 'cipher', 'encrypt',
        'encrypted', 'decrypt', 'decrypted', 'hack', 'hacker', 'hacking', 'security',
        'admin', 'user', 'login', 'access', 'root', 'shell', 'file', 'answer', 'solution',
        'congratulations', 'congrats', 'well', 'done', 'nice', 'job', 'good', 'luck',
        'challenge', 'solved', 'correct', 'success', 'here', 'there', 'is', 'am',
        'zero', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
        'eleven', 'twelve', 'thirteen', 'fifteen', 'twenty', 'thirty', 'forty', 'fifty',
        'sixty', 'seventy', 'eighty', 'ninety', 'hundred', 'thousand', 'million',
        'second', 'third', 'fourth', 'fifth', 'once', 'twice', 'half', 'dozen',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        'january', 'february', 'march', 'april', 'june', 'july', 'august', 'september',
        'october', 'november', 'december', 'today', 'tomorrow', 'yesterday', 'tonight',
        'days', 'weeks', 'years', 'hours', 'minutes', 'seconds', 'noon', 'midnight',
        'dawn', 'dusk', 'attack', 'defend', 'retreat', 'north', 'south', 'east', 'west',
        'meet', 'bridge', 'river', 'castle', 'king', 'queen', 'army', 'soldier', 'enemy',
        'spy', 'agent', 'mission', 'target', 'safe', 'danger', 'alert', 'signal', 'secret',
        'treasure', 'gold', 'island', 'ship', 'map', 'road', 'street', 'town', 'village',
        'red', 'blue', 'green', 'black', 'white', 'yellow', 'orange', 'purple',
        'sun', 'moon', 'star', 'sky', 'sea', 'fire', 'ice', 'wind', 'rain', 'snow',
        'tree', 'stone', 'light', 'dark', 'shadow', 'ghost', 'dragon', 'wolf', 'bear',
        'bird', 'fish', 'horse', 'lion', 'tiger', 'eagle', 'snake', 'rabbit', 'mouse',
        'food', 'bread', 'wine', 'beer', 'coffee', 'tea', 'milk', 'apple', 'cake',
        'look', 'looking', 'going', 'coming', 'doing', 'making', 'getting', 'trying',
        'went', 'came', 'saw', 'made', 'took', 'gave', 'knew', 'thought', 'got', 'left',
        'must', 'shall', 'might', 'cannot', 'dont', 'wont', 'cant', 'lets', 'thats',
        'inside', 'outside', 'above', 'below', 'behind', 'beside', 'near', 'far',
        'begins', 'ends', 'final', 'last', 'first', 'begin', 'finish', 'escape', 'lock',
        'unlock', 'door', 'window', 'wall', 'floor', 'box', 'letter', 'note', 'clue',
        'riddle', 'puzzle', 'mystery', 'detective', 'crime', 'murder', 'truth', 'lie'
    ])

    # Characters that commonly appear in real messages and flags (not penalised as noise)
    NORMAL_PUNCTUATION = set(" .,!?'\"-_{}:;()\n\r\t")

    KNOWN_FLAG_RE = re.compile(r'(?:flag|ctf|picoctf|htb|thm)\{[^{}]+\}', re.IGNORECASE)
    GENERIC_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,15}\{[A-Za-z0-9_\-!?.@#$%^&*+=:;,\' ]{3,}\}')
    
    # CTF-specific keywords (BONUS POINTS!)
    CTF_KEYWORDS = {
        'flag', 'ctf', 'challenge', 'capture', 'congratulations', 'congrats',
        'solved', 'correct', 'success', 'winner', 'pwned', 'hacked', 'cracked',
        'picoctf', 'hackthebox', 'tryhackme', 'overthewire', 'cryptohack',
        'score', 'points', 'level', 'next', 'submit', 'answer', 'solution'
    }
    
    # Flag format patterns
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',           # flag{...}
        r'FLAG\{[^}]+\}',           # FLAG{...}
        r'ctf\{[^}]+\}',            # ctf{...}
        r'CTF\{[^}]+\}',            # CTF{...}
        r'picoCTF\{[^}]+\}',        # picoCTF{...}
        r'HTB\{[^}]+\}',            # HTB{...}
        r'\w+\{[^}]{8,}\}',         # any{8+ chars}
    ]
    
    # Common bigrams and trigrams
    COMMON_BIGRAMS = set(['th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
                          'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar'])
    
    COMMON_TRIGRAMS = set(['the', 'and', 'ing', 'her', 'hat', 'his', 'tha', 'ere',
                           'for', 'ent', 'ion', 'ter', 'was', 'you', 'ith', 'ver'])
    
    
    @staticmethod
    def quick_validity_check(text, min_printable_ratio=0.5):
        """
        Fast check to eliminate obviously invalid results early.
        Returns True if worth checking further, False to skip.
        """
        if not text or len(text) == 0:
            return False
        
        # Convert to string if bytes
        if isinstance(text, bytes):
            try:
                text = text.decode('utf-8', errors='ignore')
            except:
                return False
        
        # Must have some content
        if len(text.strip()) == 0:
            return False
        
        # Check printable ratio (fast check)
        printable_count = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')
        if printable_count / len(text) < min_printable_ratio:
            return False
        
        # Filter out bell characters early
        if '\x07' in text or '\a' in text or '\b' in text:
            return False
        
        # Check for excessive null bytes
        null_ratio = text.count('\x00') / len(text) if len(text) > 0 else 0
        if null_ratio > 0.5:
            return False
        
        # Check for excessive repetition (likely garbage)
        if len(set(text)) < 3 and len(text) > 10:
            return False
        
        return True

    @staticmethod
    def is_printable(text):
        """
        Check printability and return score (0-100)
        
        Returns:
            int: Percentage of printable characters (0-100)
        """
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        
        if not text:
            return 0
        
        printable_count = sum(1 for char in text if char in string.printable)
        return int((printable_count / len(text)) * 100)
    
    @staticmethod
    def is_ascii(text):
        """
        Check ASCII compatibility and return score (0-100)
        
        Returns:
            int: 100 if all ASCII, 0 if none, proportional otherwise
        """
        if isinstance(text, bytes):
            try:
                text = text.decode('ascii')
                return 100
            except:
                # Try to count valid ASCII bytes
                valid = sum(1 for b in text if b < 128)
                return int((valid / len(text)) * 100) if text else 0
        
        try:
            text.encode('ascii')
            return 100
        except UnicodeEncodeError:
            # Count ASCII characters
            valid = sum(1 for c in text if ord(c) < 128)
            return int((valid / len(text)) * 100) if text else 0
    
    @staticmethod
    def has_common_words(text, min_words=3):
        """
        Calculate common word score (0-100)
        
        Returns:
            int: Score based on ratio of common words found
                 - 0: No common words
                 - 100: All words are common
                 - Proportional in between
        """
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        
        words = re.findall(r'\b[a-z]+\b', text.lower())
        if not words:
            return 0
        
        common_count = sum(1 for word in words if word in TextValidator.COMMON_WORDS)
        
        # Calculate base score from ratio
        ratio = common_count / len(words)
        score = int(ratio * 100)
        
        # Give bonus for having ANY common words (makes detection easier)
        if common_count > 0:
            score = min(100, score + 20)
        
        # Extra bonus if meets minimum threshold
        if common_count >= min_words:
            score = min(100, score + 15)
        
        return score
    
    @staticmethod
    def calculate_chi_squared(text):
        """Calculate chi-squared statistic for English letter frequency"""
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return float('inf')
        
        # Count only letters
        letters = [char.lower() for char in text if char.isalpha()]
        if not letters:
            return float('inf')
        
        total = len(letters)
        counter = Counter(letters)
        
        chi_squared = 0
        for letter in string.ascii_lowercase:
            observed = counter.get(letter, 0)
            expected = (TextValidator.ENGLISH_FREQ.get(letter, 0) / 100) * total
            if expected > 0:
                chi_squared += (observed - expected) ** 2 / expected
        
        return chi_squared
    
    @staticmethod
    def has_common_bigrams(text, threshold=3):
        """
        Calculate bigram score (0-100)
        
        Returns:
            int: Score based on density of common bigrams
                 - 0: No common bigrams
                 - 100: Very high density of common bigrams
        """
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        
        text = text.lower()
        if len(text) < 2:
            return 0
        
        count = 0
        for i in range(len(text) - 1):
            bigram = text[i:i+2]
            if bigram in TextValidator.COMMON_BIGRAMS:
                count += 1
        
        # Calculate density (bigrams per character)
        density = count / (len(text) - 1)
        score = int(min(100, density * 200))  # Scale to 0-100
        
        # Bonus if meets threshold
        if count >= threshold:
            score = min(100, score + 15)
        
        return score
    
    @staticmethod
    def has_common_trigrams(text, threshold=2):
        """
        Calculate trigram score (0-100)
        
        Returns:
            int: Score based on density of common trigrams
                 - 0: No common trigrams
                 - 100: Very high density of common trigrams
        """
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        
        text = text.lower()
        if len(text) < 3:
            return 0
        
        count = 0
        for i in range(len(text) - 2):
            trigram = text[i:i+3]
            if trigram in TextValidator.COMMON_TRIGRAMS:
                count += 1
        
        # Calculate density (trigrams per character)
        density = count / (len(text) - 2)
        score = int(min(100, density * 150))  # Scale to 0-100
        
        # Bonus if meets threshold
        if count >= threshold:
            score = min(100, score + 20)
        
        return score
    
    @staticmethod
    def calculate_ic(text):
        """Calculate Index of Coincidence (IC) - higher for English text"""
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        
        letters = [c.lower() for c in text if c.isalpha()]
        n = len(letters)
        if n <= 1:
            return 0
        
        freq = Counter(letters)
        ic = sum(count * (count - 1) for count in freq.values())
        ic /= (n * (n - 1))
        
        return ic * 26  # Normalize to 0-26 range, English ~1.73
    
    @staticmethod
    def contains_flag_format(text):
        """Check if text contains CTF flag format"""
        if not text:
            return False, None
        
        import re
        for pattern in TextValidator.FLAG_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return True, match.group(0)
        return False, None
    
    @staticmethod
    def has_ctf_keywords(text):
        """Check for CTF-specific keywords (bonus scoring)"""
        if not text:
            return 0
        
        text_lower = text.lower()
        keyword_count = sum(1 for keyword in TextValidator.CTF_KEYWORDS if keyword in text_lower)
        
        # Return 0-100 score
        if keyword_count >= 3:
            return 100
        elif keyword_count == 2:
            return 75
        elif keyword_count == 1:
            return 50
        return 0
    
    MAX_WORD_LEN = max(len(w) for w in COMMON_WORDS)

    @staticmethod
    def segment_words(token):
        """
        Split an unspaced token into dictionary words (e.g. 'DAYONEOFEIGHTY').
        Returns (covered_letters, [pieces]); unmatched letters are kept as single pieces.
        Two-letter words earn half credit so random text can't score well by
        chaining 'of'/'in'/'an' fragments.
        """
        lower = token.lower()
        n = len(lower)
        best = [0.0] * (n + 1)
        back = [0] * (n + 1)
        for i in range(1, n + 1):
            best[i], back[i] = best[i - 1], i - 1
            for j in range(max(0, i - TextValidator.MAX_WORD_LEN), i - 1):
                piece = lower[j:i]
                if piece in TextValidator.COMMON_WORDS:
                    gain = len(piece) if len(piece) >= 3 else len(piece) / 2
                    if best[j] + gain > best[i]:
                        best[i], back[i] = best[j] + gain, j
        pieces = []
        i = n
        while i > 0:
            pieces.append(token[back[i]:i])
            i = back[i]
        return best[n], pieces[::-1]

    @staticmethod
    def word_coverage(text, return_segmentation=False):
        """
        Fraction (0-1) of letters that belong to dictionary words.
        Single-letter tokens only count if they are 'a' or 'i' standing alone.
        Long unknown tokens are segmented, so unspaced plaintext still scores.
        """
        tokens = re.findall(r'[A-Za-z]+', text)
        total_letters = sum(len(t) for t in tokens)
        if total_letters == 0:
            return (0.0, None) if return_segmentation else 0.0
        covered = 0
        segmented_any = False
        readable = []
        for token in tokens:
            lower = token.lower()
            if len(lower) == 1:
                if lower in ('a', 'i'):
                    covered += 1
                readable.append(token)
            elif lower in TextValidator.COMMON_WORDS:
                covered += len(lower)
                readable.append(token)
            elif 6 <= len(lower) <= 500:
                gained, pieces = TextValidator.segment_words(token)
                covered += gained
                readable.append(' '.join(pieces))
                segmented_any = segmented_any or len(pieces) > 1
            else:
                readable.append(token)
        coverage = covered / total_letters
        if return_segmentation:
            return coverage, (' '.join(readable) if segmented_any else None)
        return coverage

    @staticmethod
    def noise_ratio(text):
        """Fraction (0-1) of characters that are neither alphanumeric nor normal punctuation"""
        if not text:
            return 1.0
        noisy = sum(1 for c in text
                    if not c.isalnum() and c not in TextValidator.NORMAL_PUNCTUATION)
        return noisy / len(text)

    @staticmethod
    def case_chaos_ratio(text):
        """
        Fraction (0-1) of letters in words with random-looking case (e.g. 'iAYguAnOR').
        lowercase, UPPERCASE, Capitalized and camelCase-with-one-hump words are fine.
        """
        tokens = re.findall(r'[A-Za-z]{3,}', text)
        total = sum(len(t) for t in tokens)
        if total == 0:
            return 0.0
        chaotic = 0
        for token in tokens:
            if token.islower() or token.isupper() or token.istitle():
                continue
            transitions = sum(1 for a, b in zip(token, token[1:]) if a.isupper() != b.isupper())
            if transitions > 2:
                chaotic += len(token)
        return chaotic / total

    @staticmethod
    def analyze_text(text, original_length=None, regex_filter=None):
        """
        Perform comprehensive text analysis with improved scoring.
        
        Args:
            text: The text to analyze
            original_length: Optional length of original input (for length ratio checking)
            regex_filter: Optional regex pattern to filter results
        
        Returns:
            Dictionary with analysis results and overall score (0-100)
        """
        # Quick validity check - early termination for garbage
        if not TextValidator.quick_validity_check(text):
            return {
                'is_valid': False,
                'score': 0,
                'reason': 'Failed quick validity check',
                'length': len(text) if text else 0,
                'printable_ratio': 0
            }
        
        if isinstance(text, bytes):
            try:
                text_str = text.decode('utf-8', errors='ignore')
            except:
                return {
                    'is_valid': False,
                    'error': 'Cannot decode as text',
                    'score': 0,
                    'likely_english': False,
                    'length_ratio': 0,
                    'length_penalty': 0
                }
        else:
            text_str = text
        
        if not text_str or len(text_str) == 0:
            return {
                'is_valid': False,
                'error': 'Empty text',
                'score': 0,
                'likely_english': False,
                'length_ratio': 0,
                'length_penalty': 0
            }
        
        # Length ratio check (if original length provided)
        length_ratio = 1.0        
        # Length validation - penalize suspiciously short or long outputs
        length_penalty = 0
        
        # CRITICAL: Heavily penalize very short answers (≤5 chars)
        if len(text_str) <= 5:
            length_penalty = -50  # Heavy penalty for extremely short results
        elif len(text_str) <= 10:
            length_penalty = -30  # Moderate penalty for very short results
        
        # Additional penalty based on ratio to original input
        if original_length and original_length > 0:
            output_length = len(text_str)
            length_ratio = output_length / original_length
            
            # Penalize suspiciously short outputs
            # If output is < 10% of input and input is substantial (>50 chars), add penalty
            if original_length > 50 and length_ratio < 0.1:
                # Very suspicious - likely wrong
                length_penalty += -30
            elif original_length > 100 and length_ratio < 0.05:
                # Extremely suspicious
                length_penalty += -40
            elif original_length > 200 and length_ratio < 0.02:
                # Almost certainly wrong
                length_penalty += -50
            # Also penalize extremely long outputs (possible garbage)
            elif length_ratio > 5.0 and original_length > 50:
                # Output much longer than input - suspicious
                length_penalty += -20
            elif length_ratio > 10.0:
                # Extremely long - very suspicious
                length_penalty += -30
        
        chi_squared = TextValidator.calculate_chi_squared(text_str)
        ic = TextValidator.calculate_ic(text_str)
        
        # Get validation scores (all return 0-100 now)
        printable_score = TextValidator.is_printable(text_str)
        ascii_score = TextValidator.is_ascii(text_str)
        common_words_score = TextValidator.has_common_words(text_str)
        bigrams_score = TextValidator.has_common_bigrams(text_str)
        trigrams_score = TextValidator.has_common_trigrams(text_str)
        
        analysis = {
            'length': len(text_str),
            'printable_score': printable_score,
            'ascii_score': ascii_score,
            'common_words_score': common_words_score,
            'bigrams_score': bigrams_score,
            'trigrams_score': trigrams_score,
            'chi_squared': chi_squared,
            'index_of_coincidence': ic,
            'letter_count': sum(1 for c in text_str if c.isalpha()),
            'digit_count': sum(1 for c in text_str if c.isdigit()),
            'space_count': sum(1 for c in text_str if c.isspace()),
            'special_char_count': sum(1 for c in text_str if not c.isalnum() and not c.isspace()),
            'word_count': TextValidator.word_count(text_str),
            'entropy': TextValidator.entropy(text_str),
            # Legacy boolean fields for backward compatibility
            'is_printable': printable_score >= 90,
            'is_ascii': ascii_score >= 90,
            'has_common_words': common_words_score >= 30,
            'has_common_bigrams': bigrams_score >= 30,
            'has_common_trigrams': trigrams_score >= 30,
        }
        
        coverage, segmented = TextValidator.word_coverage(text_str, return_segmentation=True)
        noise = TextValidator.noise_ratio(text_str)
        case_chaos = TextValidator.case_chaos_ratio(text_str)
        known_flag = TextValidator.KNOWN_FLAG_RE.search(text_str)
        generic_flag = None
        if not known_flag and text_str.count('{') == text_str.count('}') == 1:
            generic_flag = TextValidator.GENERIC_FLAG_RE.search(text_str)
        letter_count = analysis['letter_count']
        distinct_letters = len(set(c.lower() for c in text_str if c.isalpha()))
        
        analysis.update({
            'word_coverage': round(coverage, 3),
            'noise_ratio': round(noise, 3),
            'case_chaos': round(case_chaos, 3),
            'flag': (known_flag or generic_flag).group(0) if (known_flag or generic_flag) else None,
            'segmented': segmented if coverage >= 0.6 else None,
        })
        
        score = 0
        
        # Printable characters (0-10)
        score += int((printable_score / 100) * 10)
        
        # Dictionary word coverage (0-35) - the strongest single signal for real text.
        # Scaled down when there are only a handful of letters to judge.
        score += int(coverage * 35 * min(1.0, letter_count / 8))
        
        # Chi-squared (0-15) - unreliable on very short text, so give a neutral score there
        if letter_count < 8:
            score += 5
        elif chi_squared < 30:
            score += 15
        elif chi_squared < 60:
            score += 10
        elif chi_squared < 150:
            score += 5
        
        # Index of Coincidence (0-10) - only meaningful with enough letters
        if letter_count < 20:
            score += 3
        else:
            ic_diff = abs(ic - 1.73)
            if ic_diff < 0.15:
                score += 10
            elif ic_diff < 0.35:
                score += 6
            elif ic_diff < 0.6:
                score += 3
        
        # Bigrams and trigrams (0-15)
        score += int((bigrams_score / 100) * 8)
        score += int((trigrams_score / 100) * 7)
        
        # Reasonable letter ratio (0-10), ignoring whitespace so spacing isn't rewarded
        non_space = analysis['length'] - analysis['space_count']
        if non_space > 0:
            letter_ratio = letter_count / non_space
            if letter_ratio >= 0.6:
                score += 10
            elif letter_ratio >= 0.35:
                score += 5
        
        # Penalties for garbage-looking output
        score -= int(noise * 80)
        score -= int(case_chaos * 30)
        # Mostly-whitespace output (e.g. XOR turning letters into tabs/newlines)
        if analysis['length'] and analysis['space_count'] / analysis['length'] > 0.5:
            score -= 40
        # Real text of 10+ letters rarely uses so few distinct letters ('ANDAANDANDAN')
        if letter_count >= 10 and distinct_letters / letter_count < 0.4 and distinct_letters < 8:
            score -= 30
        
        # Bonuses: flags, CTF keywords, user-supplied regex
        if known_flag:
            score += 40
        elif generic_flag:
            score += 20
        if TextValidator.has_ctf_keywords(text_str) and coverage >= 0.5:
            score += 5
        if regex_filter:
            try:
                if re.search(regex_filter, text_str):
                    score += 40
                    analysis['regex_match'] = True
            except re.error:
                pass
        
        # Flags are short by nature; don't let the length penalty bury them
        if known_flag or generic_flag:
            length_penalty = max(length_penalty, -10)
        score += length_penalty
        
        analysis['score'] = max(0, min(100, score))  # Cap between 0-100
        analysis['likely_english'] = score >= 50
        analysis['is_valid'] = True
        analysis['length_ratio'] = length_ratio
        analysis['length_penalty'] = length_penalty
        
        return analysis
    
    @staticmethod
    def word_count(text):
        """Count words in text"""
        if isinstance(text, bytes):
            try:
                text = text.decode()
            except:
                return 0
        return len(re.findall(r'\b\w+\b', text))
    
    @staticmethod
    def entropy(text):
        """Calculate Shannon entropy of text"""
        if isinstance(text, bytes):
            data = text
        else:
            data = text.encode()
        
        if not data:
            return 0
        
        counter = Counter(data)
        length = len(data)
        entropy = 0
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


# ============================================================================
# AUTOMATED SOLVER - Try all combinations
# ============================================================================



# ============================================================================
# ARTIFACT DETECTOR - Detect known encoding patterns and hints
# ============================================================================

class ArtifactDetector:
    """Detect known encoding artifacts and patterns"""
    
    # Base64 character to plaintext mappings for common CTF strings
    BASE64_HINTS = {
        'ZmxhZ': 'flag',      # "flag" in base64
        'Q1RG': 'CTF',        # "CTF" in base64
        'cGljb0': 'pico',     # "pico" in base64
        'SFR': 'HT',          # "HT" (HackTheBox)
        'eY': '{',            # "{" in base64
        'fQ': '}',            # "}" in base64
        'Zm': 'fl',           # "fl" (start of flag)
        'bGF': 'la',          # "la"
        'YWc': 'ag',          # "ag"
    }
    
    # Magic numbers for file types (hex signatures)
    MAGIC_NUMBERS = {
        '89504e47': 'PNG image',
        'ffd8ffe0': 'JPEG image (JFIF)',
        'ffd8ffe1': 'JPEG image (Exif)',
        '47494638': 'GIF image',
        '504b0304': 'ZIP archive',
        '504b0506': 'ZIP archive (empty)',
        '504b0708': 'ZIP archive (spanned)',
        '52617221': 'RAR archive',
        '1f8b08': 'GZIP compressed',
        '425a68': 'BZIP2 compressed',
        'fd377a58': 'XZ compressed',
        '7573746172': 'TAR archive',
        '25504446': 'PDF document',
        'd0cf11e0': 'Microsoft Office document',
        '4d5a': 'Windows executable (EXE/DLL)',
        '7f454c46': 'Linux ELF executable',
        'cafebabe': 'Java class file',
        '213c617263683e': 'Unix archive',
    }
    
    @staticmethod
    def detect_artifacts(data):
        """
        Detect known artifacts and patterns in data
        Returns hints about likely encoding/format
        """
        hints = []
        confidence = {}
        
        if not data:
            return hints, confidence
        
        # Check for Base64 padding
        if data.endswith('=='):
            hints.append('Base64 padding (==) detected - likely base64 with 1 byte padding')
            confidence['base64'] = confidence.get('base64', 0) + 40
        elif data.endswith('='):
            hints.append('Base64 padding (=) detected - likely base64 with 2 bytes padding')
            confidence['base64'] = confidence.get('base64', 0) + 35
        
        # Check for Base64 character patterns
        for b64_pattern, plaintext in ArtifactDetector.BASE64_HINTS.items():
            if b64_pattern in data:
                hints.append(f'Base64 pattern "{b64_pattern}" detected - likely contains "{plaintext}"')
                confidence['base64'] = confidence.get('base64', 0) + 25
        
        # Check for hex magic numbers
        clean_hex = data.replace(' ', '').replace('\n', '').replace('\t', '').lower()
        for magic_hex, file_type in ArtifactDetector.MAGIC_NUMBERS.items():
            if clean_hex.startswith(magic_hex):
                hints.append(f'Magic number detected - likely {file_type}')
                confidence['hex_file'] = 80
                break
            # Also check if it's in the middle (might be after decoding)
            if magic_hex in clean_hex[:100]:  # Check first 100 chars
                hints.append(f'Magic number found in data - might contain {file_type}')
                confidence['hex_file'] = 60
                break
        
        # Check for compression signatures
        if data.startswith('H4sI') or data.startswith('1f8b'):
            hints.append('GZIP signature detected')
            confidence['gzip'] = 90
        elif data.startswith('Qlo') or data.startswith('425a'):
            hints.append('BZIP2 signature detected')
            confidence['bzip2'] = 90
        elif data.startswith('/Td6') or data.startswith('fd377a58'):
            hints.append('XZ/LZMA signature detected')
            confidence['xz'] = 90
        
        # Check for URL encoding
        if data.count('%') > len(data) * 0.1:
            hints.append('High percentage of % characters - likely URL encoded')
            confidence['url_encoding'] = 70
        
        # Check for hex encoding
        hex_pattern = re.compile(r'^[0-9a-fA-F\s]+$')
        if len(data) > 10 and hex_pattern.match(data):
            if len(data.replace(' ', '')) % 2 == 0:
                hints.append('Even-length hex string detected')
                confidence['hex'] = 80
            else:
                hints.append('Odd-length hex string detected (might be missing char)')
                confidence['hex'] = 60
        
        # Check for \x hex escapes
        if r'\x' in data:
            count = data.count(r'\x')
            hints.append(f'Python hex literals (\\x) detected - {count} occurrences')
            confidence['python_literal'] = 80
        
        # Check for HTML entities
        if '&' in data and ';' in data:
            entity_pattern = re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;')
            entities = entity_pattern.findall(data)
            if entities:
                hints.append(f'HTML entities detected - {len(entities)} occurrences')
                confidence['html_entities'] = 70
        
        # Check for Morse code
        morse_pattern = re.compile(r'^[\.\-\s/]+$')
        if morse_pattern.match(data):
            hints.append('Morse code pattern detected (dots and dashes)')
            confidence['morse'] = 85
        
        # Check for binary string
        binary_pattern = re.compile(r'^[01\s]+$')
        if binary_pattern.match(data) and len(data) > 8:
            if len(data.replace(' ', '')) % 8 == 0:
                hints.append('Binary string detected (8-bit aligned)')
                confidence['binary'] = 85
            else:
                hints.append('Binary string detected (not 8-bit aligned)')
                confidence['binary'] = 70
        
        # Check for repeated patterns
        if len(data) >= 4:
            for chunk_size in [2, 3, 4]:
                chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
                if len(chunks) > 2:
                    most_common = Counter(chunks).most_common(1)[0]
                    if most_common[1] > len(chunks) * 0.3:
                        hints.append(f'Repeated {chunk_size}-char pattern detected: "{most_common[0]}" ({most_common[1]} times)')
                        confidence['repeated_pattern'] = 60
                        break
        
        # Check for Base32 (ends with ====, ===, ==, = and uses A-Z2-7)
        base32_pattern = re.compile(r'^[A-Z2-7=\s]+$')
        if base32_pattern.match(data):
            if data.endswith('===='):
                hints.append('Base32 padding (====) detected')
                confidence['base32'] = 85
            elif data.endswith('='):
                hints.append('Base32-like pattern detected')
                confidence['base32'] = 70
        
        # Check for Base85/ASCII85
        if data.startswith('<~') and data.endswith('~>'):
            hints.append('ASCII85 delimiters detected')
            confidence['ascii85'] = 95
        
        # Check for UUencode
        if data.startswith('begin ') or re.match(r'^M[!-`]+', data):
            hints.append('UUencode pattern detected')
            confidence['uuencode'] = 80
        
        # Check for JWT (three base64 parts separated by dots)
        if data.count('.') == 2:
            parts = data.split('.')
            if all(len(p) > 0 for p in parts):
                hints.append('JWT structure detected (three dot-separated parts)')
                confidence['jwt'] = 75
        
        # Check for ROT13/Caesar indicators
        if all(c.isalpha() or c.isspace() for c in data):
            # Check if it's all caps or mixed
            if data.isupper():
                hints.append('All uppercase - might be Caesar/Atbash cipher')
                confidence['caesar'] = 50
        
        # Check for Bacon cipher (A/B patterns)
        bacon_pattern = re.compile(r'^[ABab\s]+$')
        if bacon_pattern.match(data) and len(data) > 10:
            hints.append('Bacon cipher pattern detected (only A/B characters)')
            confidence['bacon'] = 80
        
        # Check for common CTF flag format hints
        if 'flag{' in data.lower() or 'ctf{' in data.lower():
            hints.append('🚩 Flag format detected in plaintext!')
            confidence['plaintext_flag'] = 100
        
        return hints, confidence
    
    @staticmethod
    def analyze_and_suggest(data):
        """
        Comprehensive analysis with suggestions
        """
        hints, confidence = ArtifactDetector.detect_artifacts(data)
        
        # Sort by confidence
        sorted_formats = sorted(confidence.items(), key=lambda x: x[1], reverse=True)
        
        suggestions = []
        if sorted_formats:
            top_format, top_conf = sorted_formats[0]
            if top_conf > 70:
                suggestions.append(f'High confidence: {top_format} ({top_conf}%)')
            elif top_conf > 50:
                suggestions.append(f'Likely: {top_format} ({top_conf}%)')
        
        return {
            'hints': hints,
            'confidence': confidence,
            'suggestions': suggestions,
            'top_format': sorted_formats[0] if sorted_formats else None
        }


    @staticmethod
    def detect_cipher_hints(text):
        """Detect hints about what cipher might be used"""
        hints = []
        
        text_upper = text.upper()
        
        # Check character set
        unique_chars = set(text_upper.replace(' ', ''))
        char_count = len(unique_chars)
        
        if char_count == 2:
            hints.append(('binary/bacon', 90, 'Only 2 unique characters - likely binary or Bacon cipher'))
        elif char_count == 5:
            hints.append(('bacon', 70, '5 unique characters - might be Bacon with ADFGX'))
        elif char_count == 32:
            hints.append(('base32', 95, 'Exactly 32 unique characters - custom base32'))
        elif char_count == 26:
            hints.append(('substitution', 60, '26 unique characters - might be simple substitution'))
        
        # Check for specific patterns
        if all(c in '01 ' for c in text):
            hints.append(('binary', 95, 'Only binary digits (0/1)'))
        
        if all(c in '.-/ ' for c in text):
            hints.append(('morse', 95, 'Contains dots and dashes - likely Morse code'))
        
        if all(c in 'ADFGVX ' for c in text_upper):
            hints.append(('adfgvx', 90, 'Only uses ADFGVX letters'))
        
        if all(c in 'ADFGX ' for c in text_upper):
            hints.append(('adfgx', 90, 'Only uses ADFGX letters'))
        
        # Check for base64 padding
        if text.endswith('==') or text.endswith('='):
            hints.append(('base64', 85, 'Ends with = padding'))
        
        # Check for hex
        if all(c in '0123456789ABCDEFabcdef ' for c in text):
            hints.append(('hexadecimal', 80, 'Only hex characters'))
        
        # Check for repeated patterns
        if len(text) >= 10:
            # Look for repeated 2-4 char sequences
            for pattern_len in [2, 3, 4]:
                patterns = {}
                for i in range(len(text) - pattern_len + 1):
                    pattern = text[i:i+pattern_len]
                    if pattern.strip():
                        patterns[pattern] = patterns.get(pattern, 0) + 1
                
                repeated = [(p, c) for p, c in patterns.items() if c >= 3]
                if repeated:
                    top_pattern = max(repeated, key=lambda x: x[1])
                    hints.append(('repeating_key', 65, f'Pattern "{top_pattern[0]}" repeats {top_pattern[1]} times - might be Vigenere'))
        
        # Check for digit/letter mix
        has_digits = any(c.isdigit() for c in text)
        has_letters = any(c.isalpha() for c in text)
        
        if has_digits and has_letters:
            digit_ratio = sum(1 for c in text if c.isdigit()) / len(text)
            if 0.3 <= digit_ratio <= 0.7:
                hints.append(('bacon_digit_letter', 70, 'Mixed digits and letters - try Bacon with digit/letter classification'))
                hints.append(('variable_rot', 60, 'Digits might indicate rotation amounts'))
        
        # Check IoC (Index of Coincidence)
        if len(text) >= 50:
            letters_only = ''.join(c for c in text_upper if c.isalpha())
            if len(letters_only) >= 50:
                from collections import Counter
                freq = Counter(letters_only)
                n = len(letters_only)
                ioc = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
                
                if ioc > 0.065:
                    hints.append(('monoalphabetic', 70, f'High IoC ({ioc:.3f}) suggests monoalphabetic substitution'))
                elif ioc < 0.045:
                    hints.append(('polyalphabetic', 70, f'Low IoC ({ioc:.3f}) suggests polyalphabetic cipher like Vigenere'))
        
        # Sort by confidence
        hints.sort(key=lambda x: x[1], reverse=True)
        
        return hints
    
    @staticmethod
    def suggest_next_steps(text, hints):
        """Suggest next steps based on detected hints"""
        suggestions = []
        
        for cipher_type, confidence, reason in hints:
            if confidence >= 80:
                if cipher_type == 'binary':
                    suggestions.append('Try binary to ASCII conversion')
                    suggestions.append('Try Bacon cipher (0=A, 1=B or vice versa)')
                elif cipher_type == 'morse':
                    suggestions.append('Try Morse code decoder with different separators')
                elif cipher_type == 'base64':
                    suggestions.append('Try base64 decoding')
                    suggestions.append('Try base64 with different padding')
                elif cipher_type == 'base32':
                    suggestions.append('Try custom base32 detection')
                elif cipher_type == 'hexadecimal':
                    suggestions.append('Try hex to ASCII conversion')
                    suggestions.append('Try hex to binary')
                elif cipher_type in ['adfgvx', 'adfgx']:
                    suggestions.append(f'Try {cipher_type.upper()} cipher with common keys')
        
        return suggestions[:5]  # Top 5 suggestions



class InputDetector:
    """Detect and convert various input formats to text"""
    
    @staticmethod
    def is_hex(text):
        """Check if text is hexadecimal"""
        # Remove common separators
        cleaned = text.replace(' ', '').replace(':', '').replace('-', '').replace('0x', '')
        if not cleaned:
            return False
        try:
            int(cleaned, 16)
            return len(cleaned) >= 2 and len(cleaned) % 2 == 0
        except ValueError:
            return False
    
    @staticmethod
    def is_base64(text):
        """Check if text is base64"""
        if not text or len(text) < 4:
            return False
        # Base64 uses A-Z, a-z, 0-9, +, /, =
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        # Must be mostly base64 characters
        valid_ratio = sum(c in base64_chars for c in text) / len(text)
        # Length must be multiple of 4 (with padding) or close to it
        return valid_ratio > 0.9 and len(text) % 4 == 0
    
    @staticmethod
    def is_binary(text):
        """Check if text is binary (0s and 1s)"""
        if not text:
            return False
        cleaned = text.replace(' ', '').replace('\n', '').replace('\t', '')
        return len(cleaned) >= 8 and all(c in '01' for c in cleaned)
    
    @staticmethod
    def is_binary(text):
        """Check if text is binary"""
        cleaned = text.replace(' ', '').replace('\n', '')
        if not cleaned:
            return False
        # Must be only 0s and 1s, and reasonable length (multiple of 8 preferred)
        return all(c in '01' for c in cleaned) and len(cleaned) >= 8
    
    @staticmethod
    def is_octal(text):
        """Check if text is octal"""
        cleaned = text.replace(' ', '').replace('\n', '')
        if not cleaned:
            return False
        # Must be only 0-7, and reasonable length
        return all(c in '01234567' for c in cleaned) and len(cleaned) >= 3
    
    @staticmethod
    def is_decimal_sequence(text):
        """Check if text is space/comma-separated decimal numbers"""
        # Try space-separated
        parts = text.replace(',', ' ').split()
        if len(parts) < 2:
            return False
        try:
            numbers = [int(p) for p in parts]
            # Should be ASCII-range mostly
            return all(0 <= n <= 255 for n in numbers)
        except ValueError:
            return False
    
    @staticmethod
    def is_base64_like(text):
        """Check if text looks like base64"""
        # Base64 uses A-Z, a-z, 0-9, +, /, =
        cleaned = text.replace('\n', '').replace(' ', '')
        if len(cleaned) < 4:
            return False
        
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        char_match = sum(1 for c in cleaned if c in base64_chars)
        
        # If >90% characters are base64 chars and length is multiple of 4 (with padding)
        return (char_match / len(cleaned)) > 0.9 and len(cleaned) % 4 == 0
    
    @staticmethod
    def is_morse_like(text):
        """Check if text looks like morse code"""
        # Morse uses dots, dashes, spaces, slashes
        morse_chars = set('.-/ \n\t')
        if not text:
            return False
        char_match = sum(1 for c in text if c in morse_chars)
        return (char_match / len(text)) > 0.8 and ('.' in text or '-' in text)
    
    @staticmethod
    def normalize_input(text):
        """
        Normalize input from various formats to plain text
        Attempts to detect and convert hex, base64, binary, etc.
        """
        if not text:
            return text
        
        # Try to detect and convert
        if InputDetector.is_hex(text):
            try:
                cleaned = text.replace(' ', '').replace(':', '').replace('-', '').replace('0x', '')
                decoded = bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
                if decoded:
                    return decoded
            except:
                pass
        
        if InputDetector.is_binary(text):
            try:
                cleaned = text.replace(' ', '').replace('\n', '').replace('\t', '')
                # Convert binary string to bytes
                byte_array = []
                for i in range(0, len(cleaned), 8):
                    byte = cleaned[i:i+8]
                    if len(byte) == 8:
                        byte_array.append(int(byte, 2))
                decoded = bytes(byte_array).decode('utf-8', errors='ignore')
                if decoded:
                    return decoded
            except:
                pass
        
        if InputDetector.is_base64(text):
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                if decoded:
                    return decoded
            except:
                pass
        
        # If no conversion worked, return original
        return text
    
    @staticmethod
    def is_url_encoded(text):
        """Check if text is URL encoded"""
        return '%' in text and any(c in '0123456789ABCDEFabcdef' for c in text)
    
    @staticmethod
    def detect_format(text):
        """Detect the format of input text"""
        formats = []
        
        if InputDetector.is_hex(text):
            formats.append('hex')
        
        if InputDetector.is_binary(text):
            formats.append('binary')
        
        if InputDetector.is_octal(text):
            formats.append('octal')
        
        if InputDetector.is_decimal_sequence(text):
            formats.append('decimal')
        
        if InputDetector.is_base64_like(text):
            formats.append('base64')
        
        if InputDetector.is_morse_like(text):
            formats.append('morse')
        
        if InputDetector.is_url_encoded(text):
            formats.append('url_encoded')
        
        if not formats:
            formats.append('text')
        
        return formats
    
    @staticmethod
    def convert_from_format(text, format_type):
        """Convert text from detected format to plain text"""
        try:
            if format_type == 'hex':
                cleaned = text.replace(' ', '').replace(':', '').replace('-', '').replace('0x', '')
                return bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
            
            elif format_type == 'binary':
                cleaned = text.replace(' ', '').replace('\n', '')
                # Process in 8-bit chunks
                result = []
                for i in range(0, len(cleaned), 8):
                    chunk = cleaned[i:i+8]
                    if len(chunk) == 8:
                        result.append(chr(int(chunk, 2)))
                return ''.join(result)
            
            elif format_type == 'octal':
                cleaned = text.replace(' ', '').replace('\n', '')
                # Process in 3-digit chunks
                result = []
                for i in range(0, len(cleaned), 3):
                    chunk = cleaned[i:i+3]
                    if chunk:
                        result.append(chr(int(chunk, 8)))
                return ''.join(result)
            
            elif format_type == 'decimal':
                parts = text.replace(',', ' ').split()
                return ''.join(chr(int(p)) for p in parts if 0 <= int(p) <= 1114111)
            
            elif format_type == 'base64':
                return Encodings.from_base64(text)
            
            elif format_type == 'morse':
                return Encodings.from_morse(text)
            
            elif format_type == 'url_encoded':
                return Encodings.from_url_encoding(text)
            
            else:  # text
                return text
        
        except Exception:
            return None
    
    @staticmethod
    def try_all_formats(text):
        """Try converting text from all possible formats"""
        formats = InputDetector.detect_format(text)
        results = {}
        
        for fmt in formats:
            converted = InputDetector.convert_from_format(text, fmt)
            if converted and converted != text:
                results[fmt] = converted
        
        return results



import multiprocessing as mp
from functools import partial


from functools import lru_cache
import hashlib
import threading
from concurrent.futures import ProcessPoolExecutor, as_completed

class ResultCache:
    """Cache for decoded results to avoid redundant processing"""
    
    def __init__(self, maxsize=10000):
        self.cache = {}
        self.maxsize = maxsize
    
    def get_hash(self, text, method):
        """Generate cache key"""
        return hashlib.md5(f"{text}:{method}".encode()).hexdigest()
    
    def get(self, text, method):
        """Get cached result"""
        key = self.get_hash(text, method)
        return self.cache.get(key)
    
    def set(self, text, method, result):
        """Cache result"""
        if len(self.cache) >= self.maxsize:
            # Clear 20% of cache when full
            items_to_remove = list(self.cache.keys())[:self.maxsize // 5]
            for k in items_to_remove:
                del self.cache[k]
        
        key = self.get_hash(text, method)
        self.cache[key] = result
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()

# Global cache instance
_result_cache = ResultCache()



def _process_encoding_worker(args):
    """Top-level function for pickling - processes encoding methods"""
    method_name, method_path, data, min_score, original_length, regex_filter = args
    try:
        # Dynamically get the method from path (e.g., "Encodings.from_base64")
        if '.' in method_path:
            class_name, method_name_func = method_path.rsplit('.', 1)
            if class_name == 'Encodings':
                method_func = getattr(Encodings, method_name_func)
            elif class_name == 'Transformers':
                method_func = getattr(Transformers, method_name_func)
            else:
                return None
        else:
            return None
        
        decoded = method_func(data)
        decoded = Transformers.remove_bell_chars(decoded) if decoded else decoded
        if decoded and decoded != data:
            analysis = TextValidator.analyze_text(decoded, original_length, regex_filter)
            if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                return {
                    'method': method_name,
                    'chain': [method_name],
                    'decoded': decoded,
                    'analysis': analysis,
                    'score': analysis['score']
                }
    except Exception:
        pass
    return None


class ParallelProcessor:
    """Handle parallel processing using SEPARATE PROCESSES - true multi-core!"""
    
    @staticmethod
    def process_encoding(args):
        """Process a single encoding method"""
        method_name, method_path, data, min_score, original_length, regex_filter = args
        try:
            # Dynamically get the method from path (e.g., "Encodings.from_base64")
            if '.' in method_path:
                class_name, method_name_func = method_path.rsplit('.', 1)
                if class_name == 'Encodings':
                    method_func = getattr(Encodings, method_name_func)
                elif class_name == 'Transformers':
                    method_func = getattr(Transformers, method_name_func)
                else:
                    return None
            else:
                return None
            
            decoded = method_func(data)
            decoded = Transformers.remove_bell_chars(decoded) if decoded else decoded
            if decoded and decoded != data:
                analysis = TextValidator.analyze_text(decoded, original_length, regex_filter)
                if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                    return {
                        'method': method_name,
                        'chain': [method_name],
                        'decoded': decoded,
                        'analysis': analysis,
                        'score': analysis['score']
                    }
        except Exception:
            pass
        return None
    
    @staticmethod
    def process_transform(args):
        """Process a single transform method"""
        return ParallelProcessor.process_encoding(args)
    
    @staticmethod
    def parallel_process(tasks, num_cores=None):
        """Process tasks in parallel using SEPARATE PROCESSES - true multi-core!"""
        if num_cores is None:
            num_cores = max(1, mp.cpu_count() - 1)
        
        if num_cores <= 1 or len(tasks) < 10:
            # Sequential for small task sets
            return [result for result in (ParallelProcessor.process_task(t) for t in tasks) if result]
        
        # First try ProcessPoolExecutor
        try:
            print(f"  🔧 Creating {num_cores} separate worker processes...")
            results = []
            
            # Use ProcessPoolExecutor with 'spawn' explicitly
            with ProcessPoolExecutor(max_workers=num_cores, mp_context=mp.get_context('spawn')) as executor:
                # Submit all tasks and get futures
                future_to_task = {
                    executor.submit(ParallelProcessor.process_task, task): task 
                    for task in tasks
                }
                
                # Collect results as they complete
                completed = 0
                try:
                    for future in as_completed(future_to_task, timeout=1800):  # 30 min total
                        completed += 1
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                        except Exception as e:
                            pass
                        
                        # Progress update every 10 tasks
                        if completed % 10 == 0:
                            print(f"     Progress: {completed}/{len(tasks)} ({completed*100//len(tasks)}%) - {len(results)} results so far")
                
                except TimeoutError:
                    print(f"  ⚠️  Overall timeout reached, collected {len(results)} results")
            
            print(f"  ✅ Parallel processing complete ({len(results)} successful results)")
            return results
            
        except RuntimeError as e:
            # RuntimeError usually means we're in an environment where multiprocessing can't work
            # (e.g., IPython, Jupyter, or script without if __name__ guard)
            print(f"  ⚠️  Can't use multiprocessing in this environment, using sequential")
            print(f"      (Run from a .py file with 'if __name__ == \"__main__\":' to enable multiprocessing)")
            return [result for result in (ParallelProcessor.process_task(t) for t in tasks) if result]
            
        except Exception as e:
            print(f"  ⚠️  Process pool failed ({type(e).__name__}: {str(e)[:50]}), using sequential")
            return [result for result in (ParallelProcessor.process_task(t) for t in tasks) if result]
    
    @staticmethod
    def process_task(task):
        """Generic task processor"""
        task_type = task[0]
        if task_type == 'encoding':
            return ParallelProcessor.process_encoding(task[1:])
        elif task_type == 'transform':
            return ParallelProcessor.process_transform(task[1:])
        return None



class AutoSolver:
    """Automated solver that tries all combinations of methods"""
    
    # Common keys for various ciphers - EXPANDED
    
    # MASSIVE KEY EXPANSION FOR CTF CHALLENGES
    COMMON_VIGENERE_KEYS_EXPANDED = [
        # Original keys (keep all existing)
        'KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'CRYPTO', 'FLAG',
        'HIDDEN', 'MESSAGE', 'ENIGMA', 'ENCODE', 'DECODE', 'LOCKED',
        
        # CTF-specific
        'CTF', 'BSIDES', 'HACKTHEBOX', 'HTB', 'DEFCON', 'PICOCTF',
        'LONDON', 'BLACKHAT', 'HACKER', 'SECURITY', 'INFOSEC',
        'PWNED', 'OWNED', 'CRACKED', 'SOLVED', 'CHALLENGE',
        
        # Common passwords
        'ADMIN', 'ROOT', 'USER', 'GUEST', 'TEST', 'DEMO',
        'PASSWORD123', 'QWERTY', 'LETMEIN', 'WELCOME',
        
        # Dictionary words
        'CAT', 'DOG', 'BIRD', 'FISH', 'BEAR', 'WOLF', 'LION', 'TIGER',
        'ALPHA', 'BETA', 'GAMMA', 'DELTA', 'EPSILON', 'OMEGA',
        'APPLE', 'BANANA', 'CHERRY', 'ORANGE', 'GRAPE',
        'COMPUTER', 'INTERNET', 'NETWORK', 'SERVER', 'CLIENT',
        
        # Years and numbers as words
        'TWENTY', 'THIRTY', 'FORTY', 'FIFTY', 'HUNDRED', 'THOUSAND',
        'ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN',
        
        # Crypto-themed
        'ENCRYPTION', 'DECRYPTION', 'VIGENERE', 'CAESAR', 'PLAYFAIR',
        'ENIGMA', 'ADFGVX', 'BACON', 'MORSE', 'BINARY', 'HEXADECIMAL',
        
        # Common phrases (no spaces)
        'HELLOWORLD', 'TESTMESSAGE', 'SECRETKEY', 'TOPSECRET',
        'CONFIDENTIAL', 'CLASSIFIED', 'RESTRICTED',
        
        # Reversals
        'YEK', 'TERCES', 'DROWSSAP', 'REHPIC', 'EDOC', 'OTPYRC',
        
        # Single letters repeated
        'AAA', 'AAAA', 'AAAAA', 'BBB', 'BBBB', 'CCC', 'CCCC',
        'XXX', 'XXXX', 'YYY', 'YYYY', 'ZZZ', 'ZZZZ',
        
        # Colors
        'RED', 'BLUE', 'GREEN', 'YELLOW', 'BLACK', 'WHITE', 'PURPLE', 'ORANGE',
        
        # Months
        'JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE',
        'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER', 'NOVEMBER', 'DECEMBER',
        'JAN', 'FEB', 'MAR', 'APR', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC',
        
        # Days
        'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY',
        'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN',
        
        # Planets
        'MERCURY', 'VENUS', 'EARTH', 'MARS', 'JUPITER', 'SATURN', 'URANUS', 'NEPTUNE',
        
        # Common CTF themes
        'GHOST', 'PHANTOM', 'SHADOW', 'STEALTH', 'NINJA', 'PIRATE',
        'TREASURE', 'QUEST', 'MISSION', 'OPERATION', 'PROJECT',
        
        # Technical terms
        'BUFFER', 'OVERFLOW', 'INJECTION', 'XSS', 'SQL', 'SHELL',
        'EXPLOIT', 'PAYLOAD', 'REVERSE', 'FORWARD', 'STACK', 'HEAP',
        
        # Common short words
        'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER',
        'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS', 'HOW',
    ]
    
    NUMERIC_KEYS_EXPANDED = [
        # Original patterns
        '123', '321', '1234', '4321', '12345', '54321',
        
        # Years
        '2024', '2025', '2023', '2022', '2021', '2020',
        '1337', '1234', '2000', '1999', '1998', '1997',
        
        # Common numbers
        '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
        '000', '111', '222', '333', '444', '555', '666', '777', '888', '999',
        '00', '11', '22', '33', '44', '55', '66', '77', '88', '99',
        
        # Sequential
        '123456', '654321', '1234567', '7654321', '12345678', '87654321',
        '012', '0123', '01234', '012345', '0123456', '01234567', '012345678', '0123456789',
        
        # Alternating
        '101', '1010', '10101', '010', '0101', '01010',
        '121', '1212', '12121', '212', '2121', '21212',
        '131', '1313', '13131', '141', '1414', '14141',
        
        # Repeated patterns
        '12312', '123123', '123412', '1234123', '12341234',
        '11223', '112233', '1122334', '11223344',
        
        # Special CTF numbers
        '42', '420', '1337', '31337', '8080', '8888', '9999',
        '13', '17', '23', '31', '37', '41', '43', '47',  # Primes
        
        # Fibonacci-like
        '112', '1123', '11235', '112358',
        
        # Powers
        '124', '1248', '12481', '124816',  # Powers of 2
        '139', '1927', '19273',  # Powers of 3
        
        # Phone patterns
        '2580', '1478', '3690', '1230', '0987',  # Common phone unlock patterns
    ]

    # Keep original for backward compatibility
    COMMON_VIGENERE_KEYS = [
        # Standard keys
        'KEY', 'SECRET', 'PASSWORD', 'CIPHER', 'CODE', 'FLAG', 'CTF',
        'CRYPTO', 'HELLO', 'WORLD', 'TEST', 'ADMIN', 'USER', 'PASS',
        'ABC', 'XYZ', 'QWERTY', 'LEMON', 'ZEBRA', 'BACON', 'KEYWORD',
        'DECRYPT', 'ENCRYPT', 'ENCODE', 'DECODE', 'MESSAGE', 'HIDDEN',
        'PUZZLE', 'CHALLENGE', 'SECURITY', 'PRIVATE', 'PUBLIC',
        # Theme keys - Colors
        'RED', 'BLUE', 'GREEN', 'BLACK', 'WHITE', 'YELLOW', 'ORANGE', 'PURPLE',
        'PINK', 'BROWN', 'GRAY', 'GREY', 'VIOLET', 'INDIGO', 'CYAN', 'MAGENTA',
        # Theme keys - Months
        'JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE', 
        'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER', 'NOVEMBER', 'DECEMBER',
        'JAN', 'FEB', 'MAR', 'APR', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC',
        # Theme keys - Days
        'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY',
        'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN',
        # Theme keys - Numbers
        'ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN',
        'ELEVEN', 'TWELVE', 'THIRTEEN', 'FOURTEEN', 'FIFTEEN', 'SIXTEEN',
        'TWENTY', 'THIRTY', 'FORTY', 'FIFTY', 'HUNDRED', 'THOUSAND',
        'ZERO', 'FIRST', 'SECOND', 'THIRD', 'FOURTH', 'FIFTH',
        # Theme keys - Common words
        'LOVE', 'HATE', 'TRUTH', 'FALSE', 'NORTH', 'SOUTH', 'EAST', 'WEST',
        'GOLD', 'SILVER', 'BRONZE', 'FIRE', 'WATER', 'EARTH', 'AIR',
        'LIGHT', 'DARK', 'GOOD', 'EVIL', 'TRUE', 'FALSE', 'YES', 'NO',
        'UP', 'DOWN', 'LEFT', 'RIGHT', 'HIGH', 'LOW', 'HOT', 'COLD',
        # Theme keys - Animals
        'CAT', 'DOG', 'BIRD', 'FISH', 'LION', 'TIGER', 'BEAR', 'WOLF',
        'FOX', 'DEER', 'EAGLE', 'HAWK', 'SNAKE', 'DRAGON', 'HORSE',
        # Theme keys - Countries/Cities
        'USA', 'UK', 'FRANCE', 'GERMANY', 'CHINA', 'JAPAN', 'RUSSIA',
        'LONDON', 'PARIS', 'BERLIN', 'TOKYO', 'ROME', 'MOSCOW',
        # Common short keys
        'AB', 'BC', 'CD', 'DE', 'EF', 'FG', 'GH', 'HI', 'IJ', 'JK',
        # Single letters (all)
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ]
    
    # Keys for Playfair, Beaufort, etc - EXPANDED
    COMMON_CIPHER_KEYS = [
        'KEYWORD', 'SECRET', 'KEY', 'CIPHER', 'CODE', 'FLAG', 'CTF',
        'CRYPTO', 'PUZZLE', 'HIDDEN', 'MESSAGE', 'DECODE', 'ENCRYPT',
        'PLAYFAIR', 'VIGENERE', 'BACON', 'ALPHABET', 'ZEBRA', 'LEMON'
    ]
    
    # Affine cipher parameters (a must be coprime with 26) - ALL possible
    AFFINE_PARAMS = [
        (1, 0), (1, 1), (1, 2), (1, 3), (1, 4), (1, 5),
        (3, 0), (3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 6), (3, 7), (3, 8),
        (5, 0), (5, 1), (5, 2), (5, 4), (5, 8), (5, 10),
        (7, 0), (7, 1), (7, 3), (7, 5), (7, 7),
        (9, 0), (9, 2), (9, 4), (9, 8),
        (11, 0), (11, 3), (11, 7), (11, 15),
        (15, 0), (15, 4), (15, 7), (15, 11),
        (17, 0), (17, 9), (17, 13), (17, 20),
        (19, 0), (19, 5), (19, 13), (19, 21),
        (21, 0), (21, 5), (21, 13), (21, 17),
        (23, 0), (23, 7), (23, 18), (23, 23),
        (25, 0), (25, 8), (25, 11), (25, 19), (25, 25)
    ]
    
    # Additional numeric keys for Gronsfeld
    GRONSFELD_KEYS = [
        # Single digits
        '1', '2', '3', '4', '5', '6', '7', '8', '9',
        # Two digits
        '12', '23', '34', '45', '56', '67', '78', '89', '21', '32', '43', '54', '65', '76', '87', '98',
        # Three digits
        '123', '234', '345', '456', '567', '678', '789',
        '321', '432', '543', '654', '765', '876', '987',
        '111', '222', '333', '444', '555', '666', '777', '888', '999',
        # Four digits
        '1234', '2345', '3456', '4567', '5678', '6789',
        '4321', '5432', '6543', '7654', '8765', '9876',
        '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
        # Five+ digits
        '12345', '23456', '34567', '45678', '56789',
        '54321', '65432', '76543', '87654', '98765',
        '123456', '234567', '345678', '456789', '654321', '765432', '876543', '987654',
        # Special patterns
        '101', '102', '103', '104', '105', '201', '301', '401', '501',
        '1212', '2323', '3434', '4545', '5656', '7878', '8989',
        '1357', '2468', '1230', '1470', '2580', '3690',
        '12321', '123321', '1234321', '12345321',
        '1001', '2002', '3003', '1010', '2020', '3030',
    ]
    
    # Define all decoding methods
    ENCODING_METHODS = [
        ('base64', Encodings.from_base64),
        ('base64_urlsafe', Encodings.from_base64_urlsafe),
        ('base64_reversed', Encodings.from_base64_reversed),
        ('base32', Encodings.from_base32),
        ('base32_z', Encodings.from_base32_z),
        ('base32_geohash', Encodings.from_geohash_base32),
        ('base32hex', Encodings.from_base32hex),
        ('base36', Encodings.from_base36),
        ('base36_chunks', lambda x: Encodings.from_base36_chunks(x, 2)),
        ('base45', Encodings.from_base45),
        ('base58', Encodings.from_base58),
        ('base62', Encodings.from_base62),
        ('base85', Encodings.from_base85),
        ('base16', Encodings.from_base16),
        ('hex', Encodings.from_hex),
        ('hex_reversed', Encodings.from_hex_reversed),
        ('binary', Encodings.from_binary),
        ('octal', Encodings.from_octal),
        ('url', Encodings.from_url_encoding),
        ('morse', Encodings.from_morse),
        ('quoted_printable', Encodings.from_quoted_printable),
        ('html_entities', Encodings.from_html_entities),
        ('unicode_escape', Encodings.from_unicode_escape),
        ('decimal', Encodings.from_decimal),
        ('ascii85', Encodings.from_ascii85),
        ('z85', Encodings.from_z85),
        ('crockford_base32', Encodings.from_crockford_base32),
        ('bubble_babble', Encodings.from_bubble_babble),
        ('tap_code', Encodings.from_tap_code),
        ('gray_code', Encodings.from_gray_code),
        ('bit_reversed', Encodings.from_bit_reversed),
        ('nato_phonetic', Encodings.from_nato_phonetic),
        ('yenc', Encodings.from_yenc),
        ('percent_encoding', Encodings.from_percent_encoding),
        ('q_encoding', Encodings.from_quoted_printable_q),
        ('python_literal', Encodings.from_python_string_literal),
        ('xxd_dump', Encodings.from_xxd_dump),
        ('zlib', Encodings.from_zlib),
        ('gzip', Encodings.from_gzip),
        ('bz2', Encodings.from_bz2),
        ('lzma', Encodings.from_lzma),
        ('deflate', Encodings.from_deflate),
        ('polybius', Encodings.try_as_coordinates),
        ('variable_rot', Encodings.from_variable_rot),
        ('base122', Encodings.from_base122),
        ('netstring', Encodings.from_netstring),
        ('c_escape', Encodings.from_c_escape),
        ('decimal_array', Encodings.from_decimal_array),
        ('ascii_array', Encodings.from_ascii_array),
    ]
    
    # Define all transformation methods that don't need parameters
    TRANSFORM_METHODS = [
        ('reverse', Transformers.reverse_string),
        ('reverse_words', Transformers.reverse_words),
        ('rot13', Transformers.rot13),
        ('rot5', Transformers.rot5),
        ('rot18', Transformers.rot18),
        ('rot47', Transformers.rot47),
        ('atbash', Transformers.atbash),
        ('leetspeak', Transformers.leetspeak_decode),
        ('l33t_decode', Transformers.l33t_decode),
        ('number_to_letter', Transformers.number_to_letter),
        ('polybius_decode', lambda t: Transformers.polybius_square(t, decode=True)),
        ('alternating_case', Transformers.alternating_case),
        ('bit_reversal', Transformers.bit_reversal),
        ('letters_only', Transformers.letters_only),
        ('alphanumeric_only', Transformers.alphanumeric_only),
        ('consonants_only', Transformers.consonants_only),
        ('vowels_only', Transformers.vowels_only),
        ('case_flip', Transformers.case_flip),
        ('phone_keypad', Transformers.phone_keypad_decode),
        ('keyboard_shift_right', Transformers.keyboard_shift_right),
        ('keyboard_shift_left', Transformers.keyboard_shift_left),
        ('letter_value', Transformers.letter_value_cipher),
        ('phone_t9', Transformers.phone_t9_decode),
        ('adfgvx_simple', Transformers.adfgvx_simple_decrypt),
        ('digraph_sub', Transformers.digraph_substitution),
        ('fractional_morse', Transformers.fractional_morse),
    ]
    
    @staticmethod
    def try_single_methods(data, max_results=50, min_score=25, regex_filter=None, num_cores=None):
        """Try all single decoding/transform methods with ALL parameters"""
        import multiprocessing as mp
        
        # Auto-detect CPU cores if not specified
        if num_cores is None:
            num_cores = max(1, mp.cpu_count() - 1)
        
        results = []
        original_length = len(data) if data else 0
        
        # First, check if data is compressed and try decompression
        compression_type = Encodings.is_compressed(data)
        if compression_type:
            print(f"  → Detected {compression_type} compression!")
            # Try appropriate decompression
            for comp_method, comp_func in [
                ('gzip', Encodings.from_gzip),
                ('bz2', Encodings.from_bz2),
                ('lzma', Encodings.from_lzma),
                ('zlib', Encodings.from_zlib),
                ('deflate', Encodings.from_deflate),
            ]:
                try:
                    decompressed = comp_func(data)
                    if decompressed:
                        analysis = TextValidator.analyze_text(decompressed, original_length)
                        if analysis['score'] >= min_score - 10:  # More lenient for compressed
                            results.append({
                                'text': decompressed,
                                'method': f'{comp_method}_decompress',
                                'score': analysis['score']
                            })
                            print(f"      ✓ {comp_method} successful (score: {analysis['score']})")
                except:
                    pass
        
        print(f"  → Trying string splitting variations...")
        # Try splitting variations
        split_variants = []
        
        # Alternating characters (odd/even)
        alt = Transformers.split_alternating(data)
        split_variants.append(('odd_chars', alt['odd']))
        split_variants.append(('even_chars', alt['even']))
        
        # Split in half
        if len(data) > 4:
            halves = Transformers.split_by_length(data, 2)
            split_variants.append(('first_half', halves[0]))
            split_variants.append(('second_half', halves[1]))
            # Try recombining in reverse
            split_variants.append(('halves_reversed', halves[1] + halves[0]))
        
        # Extract by case
        case_split = Transformers.extract_by_case(data)
        if case_split['upper']:
            split_variants.append(('uppercase_only', case_split['upper']))
        if case_split['lower']:
            split_variants.append(('lowercase_only', case_split['lower']))
        
        # Extract by type
        type_split = Transformers.extract_by_type(data)
        for type_name, content in type_split.items():
            if content and content != data:
                split_variants.append((f'extract_{type_name}', content))
        
        # Try each split variant
        for variant_name, variant_text in split_variants:
            if variant_text and len(variant_text) > 3:
                analysis = TextValidator.analyze_text(variant_text, original_length)
                if analysis['score'] >= min_score - 5:  # Slightly more lenient
                    results.append({
                        'text': variant_text,
                        'method': variant_name,
                        'score': analysis['score']
                    })
        
        print(f"  → Trying {len(AutoSolver.ENCODING_METHODS)} encoding methods..." + (f" (using {num_cores} cores)" if num_cores > 1 else ""))
        
        # Try encodings with parallel processing if enabled
        if num_cores > 1 and len(AutoSolver.ENCODING_METHODS) > 5:
            tasks = []
            for name, method in AutoSolver.ENCODING_METHODS:
                # Convert method to string path for pickling
                method_path = f"Encodings.{method.__name__}"
                tasks.append(('encoding', name, method_path, data, min_score, len(data), regex_filter))
            
            parallel_results = ParallelProcessor.parallel_process(tasks, num_cores)
            results.extend(parallel_results)
        else:
            # Sequential execution
            for name, method in AutoSolver.ENCODING_METHODS:
                try:
                    decoded = method(data)
                    decoded = Transformers.remove_bell_chars(decoded) if decoded else decoded
                    if decoded and decoded != data:
                        analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                        if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                            results.append({
                                'method': name,
                                'chain': [name],
                                'decoded': decoded,
                                'analysis': analysis,
                                'score': analysis['score']
                            })
                except Exception:
                    pass
        
        print(f"  → Trying {len(AutoSolver.TRANSFORM_METHODS)} transformation methods..." + (f" (using {num_cores} cores)" if num_cores > 1 else ""))
        
        # Try transformations with parallel processing if enabled
        if num_cores > 1 and len(AutoSolver.TRANSFORM_METHODS) > 5:
            tasks = []
            for name, method in AutoSolver.TRANSFORM_METHODS:
                # Convert method to string path for pickling
                method_path = f"Transformers.{method.__name__}"
                tasks.append(('transform', name, method_path, data, min_score, len(data), regex_filter))
            
            parallel_results = ParallelProcessor.parallel_process(tasks, num_cores)
            results.extend(parallel_results)
        else:
            # Sequential execution
            for name, method in AutoSolver.TRANSFORM_METHODS:
                try:
                    transformed = method(data)
                    transformed = Transformers.remove_bell_chars(transformed) if transformed else transformed
                    if transformed and transformed != data:
                        analysis = TextValidator.analyze_text(transformed, len(data), regex_filter)
                        if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                            results.append({
                                'method': name,
                                'chain': [name],
                                'decoded': transformed,
                                'analysis': analysis,
                                'score': analysis['score']
                            })
                except Exception:
                    pass
        
        print(f"  → Trying all 26 Caesar shifts...")
        # Try ALL Caesar shifts (0-25)
        try:
            shifts = Transformers.all_caesar_shifts(data)
            for shift, decoded in shifts.items():
                if decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'caesar_{shift}',
                            'chain': [f'caesar_shift_{shift}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        print(f"  → Trying all 256 XOR keys...")
        # Try ALL XOR keys (0-255)
        try:
            xor_results = Transformers.xor_bruteforce(data)
            for key, decoded in xor_results.items():
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'xor_{key}',
                            'chain': [f'xor_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        print(f"  → Trying rail fence with 2-20 rails...")
        # Try rail fence with MORE rails (2-20)
        try:
            rail_results = Transformers.all_rail_fence(data, max_rails=20)
            for rails, decoded in rail_results.items():
                if decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'railfence_{rails}',
                            'chain': [f'rail_fence_{rails}_rails'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        print(f"  → Trying Vigenere with {len(AutoSolver.COMMON_VIGENERE_KEYS)} common keys...")
        # Try Vigenere with common keys
        for key in AutoSolver.COMMON_VIGENERE_KEYS_EXPANDED:
            try:
                decoded = Transformers.vigenere_decrypt(data, key)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'vigenere_{key}',
                            'chain': [f'vigenere_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        
        # EXPANDED XOR - Try common multi-byte patterns
        common_xor_patterns = [
            b'\x00\x01', b'\x01\x02', b'\x02\x03',  # Sequential
            b'\xFF\xFF', b'\xAA\xAA', b'\x55\x55',  # Repeated
            b'\x00\xFF', b'\xFF\x00', b'\xAA\x55',  # Alternating
            b'CTF', b'KEY', b'XOR', b'ABC', b'123',      # Text-based
        ]
        
        for pattern in common_xor_patterns:
            try:
                # XOR with repeating pattern
                decoded_bytes = bytes(b ^ pattern[i % len(pattern)] 
                                     for i, b in enumerate(data.encode('latin1') if isinstance(data, str) else data))
                decoded = decoded_bytes.decode('latin1', errors='ignore')
                
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score - 5:
                        results.append({
                            'method': f'xor_pattern_{pattern.hex()}',
                            'chain': [f'xor_pattern_{pattern.hex()}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass

        print(f"  → Trying exotic ciphers (Trithemius, Playfair, Beaufort, Gronsfeld, Porta, Affine)...")
        
        # Try Trithemius cipher (progressive shift)
        try:
            decoded = Transformers.trithemius_decrypt(data)
            if decoded and decoded != data:
                analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                    results.append({
                        'method': 'trithemius',
                        'chain': ['trithemius_cipher'],
                        'decoded': decoded,
                        'analysis': analysis,
                        'score': analysis['score']
                    })
        except Exception:
            pass
        
        # Try Playfair with common keys
        for key in AutoSolver.COMMON_CIPHER_KEYS[:5]:
            try:
                # Playfair only returns encoded, but try it
                decoded = Transformers.playfair_encode(data, key)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'playfair_{key}',
                            'chain': [f'playfair_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        # Try Beaufort cipher
        for key in AutoSolver.COMMON_VIGENERE_KEYS_EXPANDED[:30]:  # Try more theme keys
            try:
                decoded = Transformers.beaufort_cipher(data, key)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'beaufort_{key}',
                            'chain': [f'beaufort_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        # Try Gronsfeld cipher with numeric keys - EXPANDED
        for key in list(AutoSolver.GRONSFELD_KEYS) + list(AutoSolver.NUMERIC_KEYS_EXPANDED):
            try:
                decoded = Transformers.gronsfeld_cipher(data, key)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'gronsfeld_{key}',
                            'chain': [f'gronsfeld_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        
        # NEW AUTOSOLVERS - Brute force with common keys
        print(f"  → Trying autokey ciphers (Beaufort, Vigenere, Variant Beaufort)...")
        
        # Beaufort Autokey
        try:
            autokey_results = Transformers.all_beaufort_autokey_decrypt(data)
            for result in autokey_results:
                decoded = result['text']
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': result['method'],
                            'chain': [result['method']],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # Variant Beaufort
        try:
            variant_results = Transformers.all_variant_beaufort_decrypt(data)
            for result in variant_results:
                decoded = result['text']
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': result['method'],
                            'chain': [result['method']],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # Vigenere Autokey
        try:
            vigenere_autokey_results = Transformers.all_vigenere_autokey_decrypt(data)
            for result in vigenere_autokey_results:
                decoded = result['text']
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': result['method'],
                            'chain': [result['method']],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # ADFGX Cipher
        try:
            adfgx_results = Transformers.all_adfgx_decrypt(data)
            for result in adfgx_results:
                decoded = result['text']
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': result['method'],
                            'chain': [result['method']],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # Substitution Cipher (Frequency Analysis)
        print(f"  → Trying substitution cipher frequency analysis...")
        try:
            sub_results = Transformers.substitution_autosolver(data)
            for result in sub_results:
                decoded = result['text']
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': result['method'],
                            'chain': [result['method']],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
# Try Affine cipher with ALL parameters - MUCH MORE
        for a, b in AutoSolver.AFFINE_PARAMS:  # Try ALL
            try:
                decoded = Transformers.affine_decrypt(data, a, b)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'affine_{a}_{b}',
                            'chain': [f'affine_a{a}_b{b}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        print(f"  → Trying transposition variations (chunks, scytale, columnar)...")
        # Try chunk reversals - EXPANDED to 20 sizes!
        for chunk_size in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 24, 25, 30]:  # Was 2-10, now 2-30!
            try:
                # Reverse chunk order
                decoded = Transformers.reverse_chunks(data, chunk_size)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'reverse_chunks_{chunk_size}',
                            'chain': [f'reverse_chunks_{chunk_size}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
                
                # Reverse each chunk
                decoded = Transformers.reverse_each_chunk(data, chunk_size)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'reverse_each_chunk_{chunk_size}',
                            'chain': [f'reverse_each_chunk_{chunk_size}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        # Try scytale - EXPANDED to 20 rails!
        for rails in range(2, 51):  # EXPANDED: Now 2-51 for maximum coverage!
            try:
                decoded = Transformers.scytale_decode(data, rails)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'scytale_{rails}',
                            'chain': [f'scytale_{rails}_rails'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        # Try columnar transposition decode - EXPANDED to 50+ keys!
        columnar_keys = [
            'KEY', 'ABCD', 'ABC', 'ABCDE', 'ABCDEF', 'ABCDEFG', 'ABCDEFGH',
            '12345', '54321', '123', '321', '1234', '4321', '123456', '654321',
            'CIPHER', 'CODE', 'SECRET', 'CRYPTO', 'FLAG', 'CTF', 'PASS',
            'DECODE', 'ENCODE', 'HIDDEN', 'SECURE', 'LOCK', 'UNLOCK',
            'ALPHA', 'BRAVO', 'DELTA', 'ECHO', 'FOXTROT', 'GOLF',
            'ZEBRA', 'TIGER', 'LION', 'BEAR', 'WOLF', 'EAGLE',
            'RED', 'BLUE', 'GREEN', 'YELLOW', 'BLACK', 'WHITE',
            'ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN',
            'ABCDEFGHI', 'ABCDEFGHIJ', 'QWERTY', 'ASDFGH', 'ZXCVBN', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'AUGUST', 'MERCURY', 'VENUS', 'EARTH', 'MARS', 'JUPITER', 'LONDON', 'PARIS', 'BERLIN', 'MADRID', 'ROME', '12345678', '87654321', '123456789', '987654321', 'UPPER', 'LOWER', 'MIXED', 'RANDOM', 'PATTERN']
        for key in columnar_keys:
            try:
                decoded = Transformers.columnar_transposition_decode(data, key)
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'columnar_{key}',
                            'chain': [f'columnar_key_{key}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
            except Exception:
                pass
        
        print(f"  → Trying Bacon variants (A/B flipped, forward/reverse)...")
        # Try Bacon cipher
        try:
            decoded = Transformers.bacon_decode(data)
            if decoded and decoded != data:
                analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                    results.append({
                        'method': 'bacon',
                        'chain': ['bacon_cipher'],
                        'decoded': decoded,
                        'analysis': analysis,
                        'score': analysis['score']
                    })
        except Exception:
            pass
        
        # Try Bacon variants
        try:
            bacon_variants = Transformers.bacon_decode_variants(data)
            for variant_name, decoded in bacon_variants.items():
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'bacon_{variant_name}',
                            'chain': [f'bacon_{variant_name}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        
        # Try Bacon with digit/letter classification (from BSides CTF solutions)
        try:
            bacon_digit_results = Transformers.bacon_decode_digit_letter(data)
            for interpretation, decoded in bacon_digit_results.items():
                if decoded and decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'bacon_digit_letter_{interpretation}',
                            'chain': [f'bacon_digit_letter_{interpretation}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # Try Variable ROT (digits as rotation indicators)
        try:
            decoded = Transformers.variable_rot_decode(data)
            if decoded and decoded != data:
                analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                    results.append({
                        'method': 'variable_rot',
                        'chain': ['variable_rot_decode'],
                        'decoded': decoded,
                        'analysis': analysis,
                        'score': analysis['score']
                    })
        except Exception:
            pass
        
        # Try custom base32 detection (32 unique chars)
        if len(set(data)) == 32:
            try:
                custom_b32_results = Encodings.detect_custom_base32(data)
                if custom_b32_results:
                    for offset_name, decoded in custom_b32_results.items():
                        if decoded and decoded != data:
                            analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                            if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                                results.append({
                                    'method': f'custom_base32_{offset_name}',
                                    'chain': [f'custom_base32_{offset_name}'],
                                    'decoded': decoded,
                                    'analysis': analysis,
                                    'score': analysis['score']
                                })
            except Exception:
                pass
        
        # Try chunked base decoding (various chunk sizes and bases)
        for chunk_size in [2, 4, 5, 6, 8, 10]:
            for base in [16, 36, 58, 62]:
                try:
                    decoded = Encodings.chunked_base_decode(data, chunk_size, base)
                    if decoded and decoded != data:
                        analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                        if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                            results.append({
                                'method': f'chunked_base{base}_size{chunk_size}',
                                'chain': [f'chunked_base{base}_size{chunk_size}'],
                                'decoded': decoded,
                                'analysis': analysis,
                                'score': analysis['score']
                            })
                except Exception:
                    pass
        
        print(f"  → Trying hidden words and anagrams...")
        # Try finding hidden words
        try:
            hidden = Transformers.find_hidden_words(data)
            if hidden:
                for pattern, decoded in list(hidden.items())[:3]:  # Top 3
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'hidden_{pattern}',
                            'chain': [f'hidden_{pattern}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        print(f"  → Trying circular shifts...")
        # Try circular string rotations
        try:
            shifts = Transformers.all_circular_shifts(data)
            for shift_amount, decoded in list(shifts.items())[:10]:  # Try first 10
                if decoded != data:
                    analysis = TextValidator.analyze_text(decoded, len(data), regex_filter)
                    if analysis.get('is_valid', False) and analysis['score'] >= min_score:
                        results.append({
                            'method': f'circular_shift_{shift_amount}',
                            'chain': [f'circular_shift_{shift_amount}'],
                            'decoded': decoded,
                            'analysis': analysis,
                            'score': analysis['score']
                        })
        except Exception:
            pass
        
        # Normalise result shape (some branches only set 'text'/'method')
        for r in results:
            if 'decoded' not in r and 'text' in r:
                r['decoded'] = r['text']
            if 'chain' not in r:
                r['chain'] = [r.get('method', 'unknown')]
            if 'analysis' not in r:
                r['analysis'] = TextValidator.analyze_text(r['decoded'], original_length, regex_filter)
        
        # Flags are already rewarded by the scorer; just annotate them
        flagged = 0
        for r in results:
            flag = r['analysis'].get('flag')
            if flag:
                r['flags_found'] = [flag]
                flagged += 1
        if flagged:
            print(f"  → 🚩 {flagged} candidate(s) contain a flag-like pattern")
        
        results.sort(key=lambda x: (x['score'], -len(x['chain'])), reverse=True)
        print(f"  ✓ Found {len(results)} promising results (score >= {min_score})")
        
        return results[:max_results]
    
    @staticmethod
    def _process_next_layer(args):
        """Worker function for parallel combination processing"""
        prev_result, min_score, max_results, regex_filter = args
        try:
            next_layer = AutoSolver.try_single_methods(
                prev_result['decoded'], 
                max_results=max_results, 
                min_score=min_score,
                regex_filter=regex_filter,
                num_cores=1  # Don't nest parallelism
            )
            
            results = []
            for result in next_layer:
                chain = prev_result.get('chain', [prev_result.get('method', 'unknown')]) + [result['method']]
                results.append({
                    'decoded': result['decoded'],
                    'chain': chain,
                    'method': ' → '.join(chain),
                    'score': result['score'],
                    'analysis': result.get('analysis', {}),
                })
            return results
        except Exception:
            return []
    
    @staticmethod
    def try_combinations(data, max_depth=3, max_results=10, min_score=30, regex_filter=None, num_cores=None):
        """
        Try combinations - MAXIMUM EXHAUSTIVE v4.0 - FULLY PARALLELIZED!
        
        Args:
            num_cores: Number of processes (None=auto-detect, uses ProcessPoolExecutor)
        """
        import multiprocessing as mp
        from concurrent.futures import ProcessPoolExecutor, as_completed
        
        # Auto-detect CPU cores if not specified
        if num_cores is None:
            num_cores = max(1, mp.cpu_count() - 1)
        
        all_results = []
        
        # Stage 1: SINGLE METHODS (Depth 1) - Already parallelized internally
        print(f"[*] Stage 1: Testing single methods (depth 1)...")
        print(f"    This tests ~1,500 individual algorithms/encodings")
        single_results = AutoSolver.try_single_methods(data, max_results=2000, min_score=min_score, regex_filter=regex_filter, num_cores=num_cores)
        
        for result in single_results:
            if result['score'] >= min_score:
                all_results.append(result)
        
        print(f"    Found {len(single_results)} candidates")
        
        # Stage 2: DOUBLE COMBINATIONS (Depth 2) - PARALLELIZED!
        if max_depth >= 2:
            print(f"[*] Stage 2: Testing double combinations (depth 2) - PARALLEL...")
            print(f"    This tests ~500K two-layer chains (e.g., Base64 → Caesar)")
            candidates = single_results[:min(500, len(single_results))]
            
            # Prepare tasks for parallel processing
            tasks = [(result, min_score - 5, 1000, regex_filter) for result in candidates]
            
            # Process in parallel
            depth2_results = []
            if num_cores > 1 and len(tasks) > 5:
                try:
                    with ProcessPoolExecutor(max_workers=num_cores, mp_context=mp.get_context('spawn')) as executor:
                        futures = {executor.submit(AutoSolver._process_next_layer, task): i for i, task in enumerate(tasks)}
                        
                        completed = 0
                        for future in as_completed(futures, timeout=1800):
                            completed += 1
                            try:
                                results = future.result()
                                depth2_results.extend(results)
                                if completed % 20 == 0:
                                    print(f"    {completed}/{len(tasks)} ({completed*100//len(tasks)}%) - {len(depth2_results)} results")
                            except Exception:
                                pass
                except Exception as e:
                    print(f"  ⚠️  Parallel failed, using sequential for depth 2")
                    for task in tasks:
                        depth2_results.extend(AutoSolver._process_next_layer(task))
            else:
                # Sequential fallback
                for i, task in enumerate(tasks):
                    if (i + 1) % 50 == 0:
                        print(f"    {i+1}/{len(tasks)}...")
                    depth2_results.extend(AutoSolver._process_next_layer(task))
            
            all_results.extend(depth2_results)
            print(f"    Depth 2 complete: {len(depth2_results)} new results")
        
        # Stage 3: TRIPLE COMBINATIONS (Depth 3) - PARALLELIZED!
        if max_depth >= 3:
            print(f"[*] Stage 3: Testing triple combinations (depth 3) - PARALLEL...")
            two_stage = [r for r in all_results if len(r.get('chain', [])) == 2]
            candidates = sorted(two_stage, key=lambda x: x['score'], reverse=True)[:400]
            
            # Prepare tasks for parallel processing
            tasks = [(result, min_score - 10, 800, regex_filter) for result in candidates]
            
            # Process in parallel
            depth3_results = []
            if num_cores > 1 and len(tasks) > 5:
                try:
                    with ProcessPoolExecutor(max_workers=num_cores, mp_context=mp.get_context('spawn')) as executor:
                        futures = {executor.submit(AutoSolver._process_next_layer, task): i for i, task in enumerate(tasks)}
                        
                        completed = 0
                        for future in as_completed(futures, timeout=1800):
                            completed += 1
                            try:
                                results = future.result()
                                depth3_results.extend(results)
                                if completed % 20 == 0:
                                    print(f"    {completed}/{len(tasks)} ({completed*100//len(tasks)}%) - {len(depth3_results)} results")
                            except Exception:
                                pass
                except Exception as e:
                    print(f"  ⚠️  Parallel failed, using sequential for depth 3")
                    for task in tasks:
                        depth3_results.extend(AutoSolver._process_next_layer(task))
            else:
                # Sequential fallback
                for i, task in enumerate(tasks):
                    if (i + 1) % 50 == 0:
                        print(f"    {i+1}/{len(tasks)}...")
                    depth3_results.extend(AutoSolver._process_next_layer(task))
            
            all_results.extend(depth3_results)
            print(f"    Depth 3 complete: {len(depth3_results)} new results")
        
        # Deduplicate, keeping the highest score (and shortest chain on ties)
        print(f"[*] Deduplicating {len(all_results)} results...")
        seen = set()
        unique = []
        for result in sorted(all_results, key=lambda x: (x['score'], -len(x.get('chain', []))), reverse=True):
            if result['decoded'] not in seen:
                seen.add(result['decoded'])
                unique.append(result)
                if len(unique) >= max_results * 10:
                    break
        
        print(f"[*] Returning top {min(max_results, len(unique))} results")
        return unique[:max_results]

    @staticmethod
    def solve(data, max_depth=3, max_results=10, min_score=40, exhaustive=True, regex_filter=None, num_cores=None):
        """Main solving method - try EVERYTHING exhaustively (up to 5 layers!)"""
        print("="*70)
        print("CRYPTO TOOLKIT - ULTRA EXHAUSTIVE AUTOMATED SOLVER")
        print("="*70)
        print(f"Input: {data[:100]}{'...' if len(data) > 100 else ''}")
        print(f"Length: {len(data)} characters")
        print(f"Mode: {'ULTRA EXHAUSTIVE (tries all parameters)' if exhaustive else 'FAST'}")
        print(f"Max depth: {max_depth} layers (up to 5 supported!)")
        print("="*70)
        print()
        
        # Step 1: Detect and convert input formats
        print("🔍 STEP 1: Detecting input format...")
        detected_formats = InputDetector.detect_format(data)
        print(f"  → Detected formats: {', '.join(detected_formats)}")
        
        # Try converting from detected formats
        conversions = InputDetector.try_all_formats(data)
        if conversions:
            print(f"  → Found {len(conversions)} possible conversions:")
            for fmt, converted in conversions.items():
                preview = converted[:50] + ('...' if len(converted) > 50 else '')
                print(f"      • {fmt}: {preview}")
        else:
            print(f"  → Input appears to be plain text")
        print()
        
        if exhaustive:
            print("Ultra exhaustive mode will try:")
            print("  ✓ All detected input formats (hex, binary, octal, decimal, etc.)")
            print("  ✓ All 26 Caesar shifts")
            print("  ✓ All 256 XOR keys")
            print("  ✓ Rail fence with 2-30 rails")
            print("  ✓ Vigenere with 208+ keys (colors, months, days, animals, etc.)")
            print("  ✓ Affine with 59 parameter combinations")
            print("  ✓ All encoding methods (25+)")
            print("  ✓ All transformation methods (45+)")
            print(f"  ✓ All combinations up to depth {max_depth}")
            print(f"  ✓ ~710+ single attempts per format")
            print(f"  ✓ Up to ~9,710+ total attempts per input!")
            print()
        
        # Collect all results
        all_results = []
        
        # Step 2: Try on original input
        print("🔍 STEP 2: Trying methods on original input...")
        results = AutoSolver.try_combinations(data, max_depth, max_results * 3, min_score,
                                              regex_filter=regex_filter, num_cores=num_cores)
        all_results.extend(results)
        print(f"  → Found {len(results)} solutions from original input")
        print()
        
        # Step 3: Try on converted formats
        if conversions:
            print("🔍 STEP 3: Trying methods on converted formats...")
            for fmt, converted in list(conversions.items())[:3]:  # Top 3 formats
                # The conversion alone may already be the answer
                analysis = TextValidator.analyze_text(converted, len(data), regex_filter)
                if analysis.get('is_valid', False):
                    all_results.append({
                        'method': fmt,
                        'chain': [f'input_{fmt}'],
                        'decoded': converted,
                        'analysis': analysis,
                        'score': analysis['score'],
                    })
                
                if max_depth <= 1:
                    continue
                
                print(f"  → Testing {fmt}-converted input...")
                format_results = AutoSolver.try_combinations(converted, max_depth - 1, max_results * 2, min_score,
                                                             regex_filter=regex_filter, num_cores=num_cores)
                
                for r in format_results:
                    r['chain'] = [f'input_{fmt}'] + r.get('chain', [r.get('method', 'unknown')])
                
                all_results.extend(format_results)
                print(f"      Found {len(format_results)} solutions from {fmt}")
            print()
        
        # Deduplicate by decoded text (ignoring surrounding whitespace),
        # keeping the best-scoring / shortest chain
        all_results.sort(key=lambda r: (r['score'], -len(r['chain'])), reverse=True)
        seen = set()
        results = []
        for r in all_results:
            key = r['decoded'].strip() if isinstance(r['decoded'], str) else r['decoded']
            if key not in seen and r['score'] >= min_score:
                seen.add(key)
                r['method'] = ' → '.join(r['chain'])
                results.append(r)
        results = results[:max_results]
        
        print(f"\n{'='*70}")
        print(f"RESULTS - Found {len(results)} solutions (score >= {min_score})")
        print(f"{'='*70}\n")
        
        # Show top results
        for i, result in enumerate(results[:max_results], 1):
            print(f"[{i}] Score: {result['score']}/100")
            print(f"    Method chain: {' → '.join(result['chain'])}")
            print(f"    Decoded: {result['decoded'][:200]}{'...' if len(result['decoded']) > 200 else ''}")
            if result['analysis'].get('segmented'):
                print(f"    Reads as: {result['analysis']['segmented'][:200]}")
            print(f"    Analysis:")
            print(f"      - Printable score: {result['analysis']['printable_score']}/100")
            print(f"      - ASCII score: {result['analysis']['ascii_score']}/100")
            print(f"      - Common words score: {result['analysis']['common_words_score']}/100")
            print(f"      - Bigrams score: {result['analysis']['bigrams_score']}/100")
            print(f"      - Trigrams score: {result['analysis']['trigrams_score']}/100")
            print(f"      - Chi-squared: {result['analysis']['chi_squared']:.2f} (lower is better)")
            print(f"      - Index of Coincidence: {result['analysis']['index_of_coincidence']:.2f} (~1.73 for English)")
            print()
        
        if not results:
            print("❌ No solutions found above threshold.")
            print("\nPossible reasons:")
            print("   - Already plaintext (try analyzing it directly)")
            print("   - Using an uncommon cipher not in the toolkit")
            print("   - Requires a specific key/password")
            print("   - Corrupted or invalid data")
            print("   - Too strong encryption")
            print("\nTry:")
            print("   - Lower min_score threshold")
            print("   - Check if it's already readable")
            print("   - Look for patterns manually")
        elif results[0]['score'] >= 80:
            print(f"✅ HIGH CONFIDENCE - Solution #{1} is very likely correct!")
        elif results[0]['score'] >= 70:
            print(f"✓ GOOD MATCH - Solution #{1} looks promising")
        elif results[0]['score'] >= 60:
            print(f"⚠ MODERATE - Solution #{1} might be correct, review carefully")
        else:
            print(f"⚠ LOW CONFIDENCE - Results may need manual review or different approach")
        
        return results


# ============================================================================
# LEGACY HELPER FUNCTIONS (for backwards compatibility)
# ============================================================================

def try_all_decodings(data):
    """Try all common encoding methods on data (legacy function)"""
    return AutoSolver.try_single_methods(data, max_results=50)


def solve_challenge(encrypted_text, max_depth=3, max_results=10, min_score=25, exhaustive=True, regex_filter=None, num_cores=None):
    """
    Attempt to solve a crypto challenge automatically with ARTIFACT DETECTION
    
    Args:
        encrypted_text: The encrypted text to solve
        max_depth: Maximum chain depth (1=single, 2=double, 3+=triple+ layers)
        max_results: Maximum number of results to return
        min_score: Minimum score threshold for valid results
        exhaustive: Use exhaustive search
        regex_filter: Optional regex pattern to filter results
        num_cores: Number of processes (None=auto-detect, 1=single-core, 2+=multi-process)
                   Now uses ProcessPoolExecutor - separate processes, won't hang!
    """
    import multiprocessing as mp
    
    # Text read from files usually ends with a newline that isn't part of the cipher
    encrypted_text = encrypted_text.strip()
    
    # Auto-detect CPU cores if not specified
    if num_cores is None:
        num_cores = max(1, mp.cpu_count() - 1)
        print(f"🚀 Auto-detected {mp.cpu_count()} CPU cores, using {num_cores} separate processes")
    elif num_cores > 1:
        print(f"🚀 Using {num_cores} separate processes for parallel processing")
    
    """
    Attempt to solve a crypto challenge automatically with ARTIFACT DETECTION
    
    Parameters:
    -----------
    encrypted_text : str
        The encrypted text to solve
    max_depth : int (default: 3)
        Maximum number of encoding/cipher layers to try (1-6)
    max_results : int (default: 10)
        Maximum number of results to return
    min_score : int (default: 25)
        Minimum score threshold (0-100) for results
    exhaustive : bool (default: True)
        If True, tries ALL possible parameters for each algorithm
        If False, uses faster but less comprehensive approach
    
    Returns:
    --------
    list : List of solution dictionaries sorted by score
    """
    print("="*80)
    print("  CRYPTO CHALLENGE SOLVER v3.0 - ULTRA EXHAUSTIVE MODE + ARTIFACT DETECTION")
    print("="*80)
    print()
    
    # Detect artifacts and patterns FIRST
    print("🔍 [STEP 1] Analyzing input for known artifacts and patterns...")
    print("-" * 80)
    artifacts = ArtifactDetector.analyze_and_suggest(encrypted_text)
    
    if artifacts['hints']:
        print("\n📋 ARTIFACTS DETECTED:")
        for hint in artifacts['hints']:
            print(f"   • {hint}")
    
    if artifacts['suggestions']:
        print("\n💡 SMART SUGGESTIONS:")
        for suggestion in artifacts['suggestions']:
            print(f"   ★ {suggestion}")
    
    if not artifacts['hints']:
        print("   No specific artifacts detected - will try all methods")
    
    print()
    print("-" * 80)
    print()
    
    # Detect and normalize input format
    print("🔧 [STEP 2] Detecting and normalizing input format...")
    if InputDetector.is_hex(encrypted_text):
        detected_format = 'hex'
    elif InputDetector.is_base64(encrypted_text):
        detected_format = 'base64'
    elif InputDetector.is_binary(encrypted_text):
        detected_format = 'binary'
    else:
        detected_format = 'text'
    
    print(f"   Format: {detected_format}")
    
    normalized = InputDetector.normalize_input(encrypted_text)
    print(f"   Normalized length: {len(normalized)} characters")
    print()
    
    # Solve
    print("🚀 [STEP 3] Attempting to solve with ultra-exhaustive search...")
    print("-" * 80)
    print()
    
    return AutoSolver.solve(encrypted_text, max_depth, max_results, min_score, exhaustive,
                            regex_filter=regex_filter, num_cores=num_cores)


# ============================================================================
# MAIN / DEMO
# ============================================================================

def main():
    """Demo of the crypto toolkit"""
    print("="*70)
    print("CRYPTO TOOLKIT - ENHANCED EDITION")
    print("="*70)
    print("Features:")
    print("  - 20+ Transformers (Caesar, Vigenere, Rail Fence, XOR, etc.)")
    print("  - 25+ Encodings (Base64, Hex, Morse, Binary, etc.)")
    print("  - Advanced Text Validation (Chi-squared, IC, n-grams)")
    print("  - Automated Solver (tries all combinations)")
    print("="*70)
    
    # Example 1: Simple encoding/decoding
    print("\n[EXAMPLE 1: Simple Encoding/Decoding]")
    text = "Hello World"
    
    b64 = Encodings.to_base64(text)
    print(f"Base64: '{text}' -> '{b64}'")
    
    morse = Encodings.to_morse(text)
    print(f"Morse:  '{text}' -> '{morse}'")
    
    # Example 2: Multi-stage encryption
    print("\n[EXAMPLE 2: Multi-Stage Encryption]")
    secret = "Secret Message"
    stage1 = Transformers.caesar_cipher(secret, 5)
    stage2 = Encodings.to_base64(stage1)
    stage3 = Transformers.reverse_string(stage2)
    print(f"Original: {secret}")
    print(f"After Caesar+5, Base64, Reverse: {stage3}")
    
    # Example 3: Auto-solve challenges
    print("\n[EXAMPLE 3: Auto-Solve ROT13]")
    encrypted1 = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"
    solve_challenge(encrypted1, max_depth=2, max_results=3)
    
    print("\n[EXAMPLE 4: Auto-Solve Base64]")
    encrypted2 = "SGVsbG8gV29ybGQh"
    solve_challenge(encrypted2, max_depth=2, max_results=3)
    
    print("\n[EXAMPLE 5: Auto-Solve Multi-Stage]")
    # This is "flag" -> base64 -> reverse -> base64
    encrypted3 = "VkdNMGJGUT0="
    solve_challenge(encrypted3, max_depth=3, max_results=5)
    
    print("\n" + "="*70)
    print("Quick Start:")
    print("  from crypto_toolkit import solve_challenge")
    print("  solve_challenge('your_encrypted_text_here')")
    print("="*70)


if __name__ == "__main__":
    main()
