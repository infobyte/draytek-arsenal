from draytek_arsenal.commands.base import Command
import yaml
from typing import Any, Dict, List
from draytek_arsenal.format import parse_firmware
from draytek_arsenal.draytek_format import Draytek

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

        struct = parse_firmware(args.firmware)

        if isinstance(struct, Draytek):
            object = {
                "type": "RTOS",
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
                "web": {
                    "header": {
                        "size": hex(struct.web.header.size),
                        "adjusted_size": hex(struct.web.header.adj_size),
                        "next_section": hex(struct.web.header.next_section)
                    },
                    "checksum": hex(struct.web.checksum)
                }
            }

        else:
            object = {
                "type": "Linux",
                "nonce": struct.nonce.decode(),
                "image_start": struct.image_start,
                "image_len": struct.image_len
            }

        print("[+] Firmware information:\n" + yaml.safe_dump(object))
