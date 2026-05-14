#!/usr/bin/env python3
"""
C2 Traffic Decryptor
[REDACTED-CF-NAMESPACE] BEC Campaign, May 2026

Decrypts AES-CBC encrypted payloads captured from C2 traffic.
The passphrase was found hardcoded in the publicly accessible
phishing page source. All captured traffic is decryptable
without additional steps.

Algorithm:  AES-CBC
Key:        SHA-256 of hardcoded passphrase
IV:         First 16 bytes of each payload
Encoding:   URL-safe base64

NOTE: PASSPHRASE below is redacted in the published version.
Substitute the actual value for operational use.

Usage:
  pip install pycryptodome
  python decryptor.py --payload "<base64 string>"
  python decryptor.py --file payloads.txt
"""

import base64
import hashlib
import json
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PASSPHRASE = '[REDACTED-AES-KEY]'


def decrypt_c2(encoded_data: str) -> dict:
    b64 = encoded_data.strip().replace('-', '+').replace('_', '/')
    while len(b64) % 4:
        b64 += '='
    raw = base64.b64decode(b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    key = hashlib.sha256(PASSPHRASE.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(decrypted.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Decrypt [REDACTED-CF-NAMESPACE] C2 traffic'
    )
    parser.add_argument('--payload', help='Single base64 payload string')
    parser.add_argument(
        '--file',
        help='Path to file containing one payload per line'
    )
    args = parser.parse_args()

    if args.payload:
        try:
            result = decrypt_c2(args.payload)
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f'Failed: {e}')

    elif args.file:
        with open(args.file, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
        for i, line in enumerate(lines):
            print(f'\n--- Payload {i+1} ---')
            try:
                result = decrypt_c2(line)
                print(json.dumps(result, indent=2))
            except Exception as e:
                print(f'Failed: {e}')

    else:
        parser.print_help()
