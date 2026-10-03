"""Encrypt/decrypt NEWDS escrow files.

Use the same NEWDS_SECRET value as the vault server. If it changes, existing
.NEWDS files cannot be decrypted with the new value.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def key_from_secret():
    secret = os.environ.get("NEWDS_SECRET", "dev-only-change-this-secret")
    return hashlib.sha256(("newds-escrow-v1:" + secret).encode("utf-8")).digest()


def encrypt(source: Path, destination: Path):
    nonce = secrets.token_bytes(12)
    destination.write_bytes(nonce + AESGCM(key_from_secret()).encrypt(nonce, source.read_bytes(), None))


def decrypt(source: Path, destination: Path):
    blob = source.read_bytes()
    if len(blob) < 28:
        raise ValueError("File terlalu pendek untuk format NEWDS.")
    destination.write_bytes(AESGCM(key_from_secret()).decrypt(blob[:12], blob[12:], None))


def main():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt NEWDS .NEWDS escrow files")
    parser.add_argument("action", choices=("enc", "dec"))
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="Path tujuan (default: tambahkan/hapus .NEWDS)")
    args = parser.parse_args()
    if args.action == "enc":
        if args.file.name.lower().endswith(".newds"):
            parser.error("File sumber sudah berakhiran .NEWDS")
        output = args.output or args.file.with_name(args.file.name + ".NEWDS")
        encrypt(args.file, output)
    else:
        if args.output:
            output = args.output
        elif args.file.name.lower().endswith(".newds"):
            output = args.file.with_name(args.file.name[:-6])
        else:
            parser.error("File decrypt harus berakhiran .NEWDS atau berikan --output")
        try:
            decrypt(args.file, output)
        except Exception as exc:
            print(f"Decrypt gagal: {exc}", file=sys.stderr)
            return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
