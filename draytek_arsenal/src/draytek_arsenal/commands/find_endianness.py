from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN


class FindEndiannessCommand(Command):

    @staticmethod
    def name() -> str:
        return "find_endianness"

    @staticmethod
    def description() -> str:
        return "Checks if the RTOS is little or big endian"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["rtos"], "kwargs": {"type": str, "help": "Path to the rtos"}},
        ]

    @staticmethod
    def execute(args) -> None:
        rtos = args.rtos

        with open(rtos, "rb") as f:
            # Try to disassembly some instructions to check the endianness
            f.seek(0x100)
            code = f.read(4)
            
            big_endian_md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
            big_endian_instructions = list(big_endian_md.disasm(code, 0))

            little_endian_md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
            little_endian_instructions = list(little_endian_md.disasm(code,0))

            if big_endian_instructions:
                print("BE: Big endian")
            elif little_endian_instructions:
                print("LE: Little endian")
            else:
                print("UNKWNOWN: Couldn't determine endianess")
