from typing import Any, Dict, List
from draytek_arsenal.commands.base import Command
from draytek_arsenal.draytek_format import Draytek
from draytek_arsenal.compression import Lz4
from os import path
from struct import pack

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
                "kwargs": {"type": str, "help": "Where to extract and decompress the RTOS"}
            },
        ]


    @staticmethod
    def description() -> str:
        return "Command used to extract and decompress Draytek packages"

  
    @staticmethod
    def execute(args) -> None:
        fw_struct = Draytek.from_file(args.firmware)

        if not path.isdir(path.dirname(args.rtos)):
            print("[x] Bad RTOS output file")
            return

        if fw_struct.bin.rtos.rtos_size != len(fw_struct.bin.rtos.data):
            print(f"[x] Data length ({len(fw_struct.bin.rtos.data)}) doesn't match with the header length ({fw_struct.bin.rtos.rtos_size})")
            return

        unstructured_bootloader = b"".join([pack(">I", integer) for integer in fw_struct.bin.bootloader.data[:-1]])

        lz4 = Lz4()
        decompressed_rtos = lz4.decompress(fw_struct.bin.rtos.data)
        with open(args.rtos, "wb") as output_file:
            output_file.write(unstructured_bootloader + decompressed_rtos)
