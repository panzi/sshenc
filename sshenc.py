#!/usr/bin/env python3

# Inspired by: https://yurichev.com/n/SSH_encrypt/

__version__ = '1.0.0'

import os
import sys

import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes

__all__ = (
    'ssh_encrypt',
    'ssh_decrypt',
)

def ssh_encrypt(pubkey: bytes, plaintext: bytes) -> bytes:
    pubkey_obj = cryptography.hazmat.primitives.serialization.load_ssh_public_key(pubkey)
    algorithm = cryptography.hazmat.primitives.hashes.SHA256()
    mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=algorithm)
    oaep = cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf, algorithm, label=None)
    ciphertext = pubkey_obj.encrypt(plaintext, oaep)
    return ciphertext

def ssh_decrypt(pirvkey: bytes, ciphertext: bytes, password: bytes|None = None) -> bytes:
    privkey_obj = cryptography.hazmat.primitives.serialization.load_ssh_private_key(pirvkey, password=password)
    algorithm = cryptography.hazmat.primitives.hashes.SHA256()
    mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=algorithm)
    oaep = cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf, algorithm, label=None)
    plainext = privkey_obj.decrypt(ciphertext, oaep)
    return plainext

def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.set_defaults(command=None)
    ap.add_argument('--version', action='store_true', default=False, help='Print version and exit.')
    subaps = ap.add_subparsers()

    encap = subaps.add_parser('encrypt', aliases=['enc'])
    encap.set_defaults(command='enc')
    encap.add_argument('-o', '--output', metavar='FILE', default=None, help='Write output to FILE instead of stdout.')
    encap.add_argument('pubkey')
    encap.add_argument('file')

    decap = subaps.add_parser('decrypt', aliases=['dec'])
    decap.set_defaults(command='dec', passprompt=False, password=None, passfile=None, passenv=None)
    grp = decap.add_mutually_exclusive_group()
    grp.add_argument('-p', '--passprompt', action='store_true', default=False, help='Prompt for password.')
    grp.add_argument('-P', '--password', help='Pass password as argument.')
    grp.add_argument('--passfile', metavar='FILE', help='Read password from FILE.')
    grp.add_argument('--passenv', metavar='NAME', help='Use environment variable NAME as password.')
    decap.add_argument('-o', '--output', metavar='FILE', default=None, help='Write output to FILE instead of stdout.')
    decap.add_argument('privkey')
    decap.add_argument('file')

    args = ap.parse_args()

    if args.version:
        print(__version__)
        return

    match args.command:
        case 'enc':
            with open(args.pubkey, 'rb') as fp:
                pubkey = fp.read()

            with open(args.file, 'rb') as fp:
                plaintext = fp.read()

            ciphertext = ssh_encrypt(pubkey, plaintext)

            output: str|None = args.output
            if output is None:
                sys.stdout.buffer.write(ciphertext)
                sys.stdout.buffer.flush()
            else:
                with open(output, 'wb') as outfp:
                    outfp.write(ciphertext)

        case 'dec':
            with open(args.privkey, 'rb') as fp:
                privkey = fp.read()

            with open(args.file, 'rb') as fp:
                ciphertext = fp.read()

            password: bytes|None = None
            if args.passprompt:
                from getpass import getpass
                password = getpass().encode()
            elif args.password is not None:
                password = args.password
            elif args.passfile is not None:
                with open(args.passfile, 'rb') as fp:
                    password = fp.read()
            elif args.passenv is not None:
                password = os.getenvb(os.fsencode(args.passenv))

            plaintext = ssh_decrypt(privkey, ciphertext, password)

            output: str|None = args.output
            if output is None:
                sys.stdout.buffer.write(plaintext)
                sys.stdout.buffer.flush()
            else:
                with open(output, 'wb') as outfp:
                    outfp.write(plaintext)

        case None:
            ap.print_help()

        case _:
            raise ValueError(f'Illegal commnad: {args.command!r}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('^C')
