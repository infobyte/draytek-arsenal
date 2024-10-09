from typing import Any, Dict, List
from draytek_arsenal.commands.base import Command
from draytek_arsenal.format import parse_firmware
from draytek_arsenal.compression import Lz4
from os import path
import tempfile
import os
import sys
from Crypto.Cipher import ChaCha20

class ExtractCommand(Command):
    @staticmethod
    def name() -> str:
        return "extract_soho"


    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}},
            {
                "flags": ["--fs", "-f"],
                "kwargs": {
                    "type": str,
                    "help": "Directory path where to extract and decompress the File System",
                    "required": False
                }
            },
            {
                "flags": ["--key"],
                "kwargs": {
                    "type": str,
                    "help": "Key used to decrypt",
                    "required": True
                }
            },
        ]


    @staticmethod
    def description() -> str:
        return "Command used to extract and decompress Draytek SOHO packages"

  
    @staticmethod
    def execute(args) -> None:
        fw = parse_firmware(args.firmware)

        dec_data = do_decrypt(fw.nonce, fw.data, args.key.encode())
        lz4_data = split_lz4_image(dec_data)

        with tempfile.NamedTemporaryFile() as tmp_file:
            print(f"[*] Writing FS to tmp file: {tmp_file.name}")
            tmp_file.write(lz4_data)

            decompress(tmp_file.name, args.fs)

            print(f"[+] Extracted in {args.fs}")


def do_decrypt(nonce: str, data: bytes, key: bytes) -> bytes:
    print(f"[*] Decrypting {len(data)} bytes with\n\tnonce: {nonce}\n\tkey: {key}")
    cipher = ChaCha20.new(key=key, nonce=nonce)
    dec_data = cipher.decrypt(data)

    print(f"[+] Decripted {len(dec_data)} bytes")

    return dec_data

def split_lz4_image(data: bytes) -> bytes:
    try:
        start = data.find(b"\x02\x21\x4C\x18")
        if start == -1:
            print("[-] Error: no lz4 header")
            exit(0)
        
        end = data.find(b"R!!!", start)
        tmp_end = end
        while tmp_end != -1:
            end = tmp_end
            tmp_end = data.find(b"R!!!", end + 1)
        
        if end == -1:
            raise Exception("Can't find end of LZ4 image")
        
        end += (0x14 - 6)
        return data[start: end]

    except Exception as e:
        print("[x] Error: split_lz4_image")
        print(e)

def decompress(input: str, output_dir: str) -> None:
    try:
        with tempfile.NamedTemporaryFile() as tmp_file:
            os.system(f"lz4 -d {input} {tmp_file.name}")
            os.system(f"mkdir -p {output_dir}")
            os.system(f"cpio -idmv  --file {tmp_file.name} -D {output_dir}")

    except Exception as e:
        print("[x] Error: decompress")
        print(e)

