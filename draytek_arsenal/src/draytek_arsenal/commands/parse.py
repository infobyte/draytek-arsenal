from draytek_arsenal.commands.base import Command
from draytek_arsenal.draytek_format import Draytek
import yaml
from typing import Any, Dict, List

class ParseCommand(Command):

    @staticmethod
    def name() -> str:
        return "parse_firmware"

    @staticmethod
    def description() -> str:
        return "Parse and show information of a Draytec firmware"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [{"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}}]

    
    @staticmethod
    def execute(args):
        struct = Draytek.from_file(args.firmware)


        object = {
            "bin": {
                "header": {
                    "size": hex(struct.bin.header.size),
                    "version_info": hex(struct.bin.header.version_info),
                    "next_section": hex(struct.bin.header.next_section.value),
                    "adjusted_size": hex(struct.bin.header.adj_size),
                    "bootloader_version": struct.bin.header.bootloader_version,
                    "product_number": struct.bin.header.product_number
                },
                "rtos": {
                    "size": hex(struct.bin.rtos.rtos_size)
                },
                "checksum": hex(struct.bin.checksum)
                
            },
            "webfs": {
                "header": {
                    "size": hex(struct.webfs.header.size),
                    "adjusted_size": hex(struct.webfs.header.adj_size),
                    "next_section": hex(struct.webfs.header.next_section)
                },
                "checksum": hex(struct.webfs.checksum)
            }
        }

        print("[+] Firmware information:\n" + yaml.safe_dump(object))
