from typing import Any, Dict, List
from draytek_arsenal.commands.base import Command
from draytek_arsenal.format import parse_firmware
from draytek_arsenal.compression import Lz4
from draytek_arsenal.fs import PFSExtractor
from os import path
from struct import pack, unpack
import tempfile
import os
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN

class PatchCommand(Command):
    @staticmethod
    def name() -> str:
        return "patch"


    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}},
            # {"flags": ["patches"], "kwargs": {"type": str, "help": "Path to the patches file"}},
            {"flags": ["output"], "kwargs": {"type": str, "help": "Path to the output file"}},
        ]

    @staticmethod
    def description() -> str:
        return "Command used to patch Draytek firmwares"

    @staticmethod
    def disasm(code):
        capmd = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        instructions = [i for i in capmd.disasm(code, 0)]
        for i in instructions:
            print(f"        {i.mnemonic} {i.op_str}")

    @staticmethod
    def patch(data, addr, patch):
        patch_offset = addr - 0x8002d478
        patch_size = len(patch)
        print("[+] Patching code @ 0x{:x}".format(patch_offset))
        PatchCommand.disasm(data[patch_offset:patch_offset+patch_size])
        print("    With:")
        PatchCommand.disasm(patch)
        data = data[:patch_offset] + patch + data[patch_offset+patch_size:]

    @staticmethod
    def v2kCheckSum(data):
        c = 0
        for i in range(0, len(data), 4):
            c+=unpack(">I", data[i:i + 4])[0]
        c = (c & 0xffffffff)
        return c
    
    @staticmethod
    def repack_fw(fw_struct, patched_rtos):
        ###############################################
        # No chequee si anda bien en el caso con DLMs #
        ###############################################     
        
        # BIN
        ## Header w/o size ni version_info | next_section  
        bin_data  = fw_struct.bin.header.rest
        ## Bootloader
        for w in fw_struct.bin.bootloader.data:
                bin_data += pack(">I", w)
        ## RTOS
        bin_data += pack(">I", len(patched_rtos))
        bin_data += patched_rtos
        bin_data += b"\x00" * (4 - (len(patched_rtos) & 0x3))   # Checksum needs len(bin_data) % 4 == 0
        ## Easier to calculate next_section here
        next_section = len(bin_data)
        ## DLMs
        if fw_struct.has_dlm:
            bin_data += fw_struct.bin.dlm.magic.encode('utf-8')
            bin_data += fw_struct.bin.dlm.data
        ## Header size and version_info | next_section     
        bin_data  = pack(">I", len(bin_data) + 12) + pack(">I", fw_struct.bin.header.version_info << 24 | next_section) + bin_data
        ## Checksum
        bin_data += pack(">I", PatchCommand.v2kCheckSum(bin_data) ^ 0xffffffff)

        # WEB
        web_data  = pack(">I", fw_struct.web.header.size)
        web_data += pack(">I", fw_struct.web.header.next_section)
        web_data += fw_struct.web.data
        web_data += fw_struct.web.padding
        web_data += pack(">I", fw_struct.web.not_checksum)

        return bin_data + web_data
    
    @staticmethod
    def execute(args) -> None:
        fw_struct = parse_firmware(args.firmware)

        if not args.output:
            print("[x] Need output filename")

        elif fw_struct.bin.rtos.rtos_size != len(fw_struct.bin.rtos.data):
            print(f"[x] Data length ({len(fw_struct.bin.rtos.data)}) doesn't match with the header length ({fw_struct.bin.rtos.rtos_size})")

        else:
            lz4 = Lz4()
            decompressed_rtos = lz4.decompress(fw_struct.bin.rtos.data)

            patched_rtos = lz4.compress(decompressed_rtos)

            repacked_fw = PatchCommand.repack_fw(fw_struct, patched_rtos)

            with open(args.output, "wb") as output_file:
                output_file.write(repacked_fw)
                

            print(f"[*] RTOS patched in {args.output}")

