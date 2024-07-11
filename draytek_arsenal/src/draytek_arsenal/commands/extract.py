from typing import Any, Dict, List
from draytek_arsenal.commands.base import Command
from draytek_arsenal.draytek_format import Draytek
from draytek_arsenal.compression import Lz4
from draytek_arsenal.fs import PFSExtractor
from os import path
from struct import pack
import tempfile
import os

class ExtractCommand(Command):
    @staticmethod
    def name() -> str:
        return "extract"


    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}},
            {
                "flags": ["--rtos", "-r"],
                "kwargs": {
                    "type": str,
                    "help": "File path where to extract and decompress the RTOS",
                    "required": False
                }
            },
            {
                "flags": ["--fs", "-f"],
                "kwargs": {
                    "type": str,
                    "help": "Directory path where to extract and decompress the File System",
                    "required": False
                }
            },
            {
                "flags": ["--dlm", "-d"],
                "kwargs": {
                    "type": str,
                    "help": "Directory path where to extract and decompress the DLMs",
                    "required": False
                }
            },
            {
                "flags": ["--dlm-key1"],
                "kwargs": {
                    "type": str,
                    "help": "First key used to decrypt DLMs",
                    "required": False
                }
            },
            {
                "flags": ["--dlm-key2"],
                "kwargs": {
                    "type": str,
                    "help": "First key used to decrypt DLMs",
                    "required": False
                }
            },
        ]


    @staticmethod
    def description() -> str:
        return "Command used to extract and decompress Draytek packages"

  
    @staticmethod
    def execute(args) -> None:
        fw_struct = Draytek.from_file(args.firmware)

        if args.rtos is None and args.dlm is None and args.fs is None:
            print(f"[x] Nothing to extract. Please set some extraction flag.")

        if args.rtos is not None:
            print("[+] Extracting RTOS from firmware")

            if not path.isdir(path.dirname(args.rtos)):
                print("[x] Bad RTOS output file")

            elif fw_struct.bin.rtos.rtos_size != len(fw_struct.bin.rtos.data):
                print(f"[x] Data length ({len(fw_struct.bin.rtos.data)}) doesn't match with the header length ({fw_struct.bin.rtos.rtos_size})")

            else:
                unstructured_bootloader = b"".join([pack(">I", integer) for integer in fw_struct.bin.bootloader.data[:-1]])

                lz4 = Lz4()
                decompressed_rtos = lz4.decompress(fw_struct.bin.rtos.data)
                with open(args.rtos, "wb") as output_file:
                    output_file.write(unstructured_bootloader + decompressed_rtos)

                print(f"[+] RTOS extracted in {args.rtos}")

        if args.dlm is not None:
            if args.dlm_key1 is None or args.dlm_key2 is None:
                print(f"[x] One or more keys are not provided")

            else:
                print("[+] Extracting DLMs from firmware")

                with tempfile.NamedTemporaryFile() as tmp_dlms:
                    print(f"[*] Writing DLMs FS to tmp file: {tmp_dlms.name}")

                    data = b"DLM/1.0" + fw_struct.bin.dlm.data
                    tmp_dlms.write(data)

                    if not path.exists(args.dlm):
                        os.makedirs(args.dlm)

                    pfs_extractor = PFSExtractor(
                        bytes.fromhex(args.dlm_key1),
                        bytes.fromhex(args.dlm_key2)
                    )
                    _ = pfs_extractor.extract(tmp_dlms.name, args.dlm)

                print(f"[+] DLMs extracted to {args.dlm}")


        if args.fs is not None:
            print("[+] Extracting FS from firmware")

            with tempfile.NamedTemporaryFile() as tmp_fs:
                print(f"[*] Writing decompressed FS to tmp file: {tmp_fs.name}")
                lz4 = Lz4()
                tmp_fs.write(
                    lz4.decompress(fw_struct.web.data)
                )

                if not path.exists(args.fs):
                    os.makedirs(args.fs)


                pfs_extractor = PFSExtractor()
                _ = pfs_extractor.extract(tmp_fs.name, args.fs)

            print(f"[+] fs extracted to {args.fs}")

        print("[*] All done..")

