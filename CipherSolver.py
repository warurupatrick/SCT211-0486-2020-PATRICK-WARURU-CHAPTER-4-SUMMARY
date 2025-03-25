#!/usr/bin/env python3

from typing import List
import binascii
import argparse

SPACE = ord(' ')


def main():
    parser = argparse.ArgumentParser(description='Many-time Pad Cracker')
    parser.add_argument(
        '--filename',
        type=str,
        help='Name of the file containing the ciphertexts (default: ciphertexts.txt)',
        default='ciphertexts.txt'
    )
    parser.add_argument(
        '-K', '--getkey',
        action='store_true',
        help='Print cracked key instead of cracked cleartexts.'
    )
    parser.add_argument(
        '-k', '--key',
        help='Encrypt messages with provided key.',
        default=''
    )
    args = parser.parse_args()
    try:
        with open(args.filename) as file:
            ciphertexts = [binascii.unhexlify(line.rstrip()) for line in file]
    except Exception as e:
        print(f'Cannot crack {args.filename} --- {e}')
        raise SystemExit(-1)
    cleartexts = [bytearray(b'?' * len(line)) for line in ciphertexts]

    if args.key:
        decrypt(ciphertexts, cleartexts, args.key)
    else:
        crack(ciphertexts, cleartexts, args.getkey)


def decrypt(ciphertexts: List[bytes], cleartexts: List[bytearray], input_key: str) -> None:
    key = binascii.unhexlify(input_key.rstrip())
    for row in range(len(ciphertexts)):
        for column in range(len(ciphertexts[row])):
            cleartexts[row][column] = ciphertexts[row][column] ^ key[column % len(key)]
        try:
            print(cleartexts[row].decode('utf-8', errors='replace'))
        except UnicodeDecodeError:
            print(cleartexts[row].decode('latin-1'))


def crack(ciphertexts: List[bytes], cleartexts: List[bytearray], getkey: bool) -> None:
    max_length = max(len(line) for line in ciphertexts)
    key = bytearray(max_length)
    key_mask = [False] * max_length

    for column in range(max_length):
        pending_ciphers = [line for line in ciphertexts if len(line) > column]
        if not pending_ciphers:
            continue

        best_score = -1
        best_candidate = None

        for cipher in pending_ciphers:
            current_byte = cipher[column]
            score = 0
            for other in pending_ciphers:
                result = current_byte ^ other[column]
                if result == 0 or chr(result).isalpha():
                    score += 1
            if score > best_score:
                best_score = score
                best_candidate = current_byte

        threshold = len(pending_ciphers) * 0.8  # 80% threshold

        if best_score >= threshold:
            key_byte = best_candidate ^ SPACE
            key[column] = key_byte
            key_mask[column] = True
            for i, cipher in enumerate(ciphertexts):
                if len(cipher) > column:
                    plain_byte = cipher[column] ^ key_byte
                    cleartexts[i][column] = plain_byte

    if getkey:
        for pos in range(max_length):
            if key_mask[pos]:
                print(f'{key[pos]:02x}', end='')
            else:
                print('__', end='')
        print()
    else:
        for line in cleartexts:
            try:
                print(line.decode('utf-8', errors='replace'))
            except UnicodeDecodeError:
                print(line.decode('latin-1'))


if __name__ == '__main__':
    main()