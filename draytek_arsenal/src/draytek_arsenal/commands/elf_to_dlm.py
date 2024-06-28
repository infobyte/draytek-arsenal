from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List

from struct import unpack, pack
from draytek_arsenal.dlm import DLM


class ElfToDlmCommand(Command):

    @staticmethod
    def name() -> str:
        return "elf_to_dlm"

    @staticmethod
    def description() -> str:
        return "Transforms a common ELF file to a DLM module."

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["elf"], "kwargs": {"type": str, "help": "Path to the file to convert"},},
            {"flags": ["output"], "kwargs": {"type": str, "help": "Output DLM file path"}},
            {"flags": ["--web-headers"], "kwargs": {"action": "store_true", "help": "Append web headers"}}
        ]

    @staticmethod
    def execute(args) -> None:
        elf_path = args.elf
        dlm_path = args.output

        print(f"[*] Crating {dlm_path} from {elf_path}")

        dlm = DLM()
        with open(elf_path, 'rb') as f:
            data = f.read()

            # El header tiene 0x24 bytes. En los primeros 0x10 va una firma para ver si
            # la version es mas nueva. 
            # En los siguientes 0x10 va un numero para ver si la licencia expiro.
            # En los ultimos 4 va un checksum

            print("[*] Packing data")
            packed_data = dlm.pack(data)

            with open(dlm_path, "wb") as o:

                if args.web_headers:
                    print("[*] Adding web header")
                    packed_data_w_header = add_web_header(packed_data)    
                    o.write(packed_data_w_header)

                else:
                    o.write(packed_data)

        print(f"[+] {dlm_path} creation success")


def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'

    c = 0

    for i in range(0, len(data), 2):
        c += unpack(">H", data[i:i+2])[0]

    c &= 0xffffffff
    c = (c >> 0x10) + (c & 0xffff)
    c = (((c >> 0x10) + c) ^ 0xffffffff) & 0xffff

    if c == 0xffff:
        c = 0

    c = c ^ 0x20140313 ^ (c << 0x10)

    return c

def add_web_header(data):
     # agregar header sin checksum porque eso cuenta
    version  = b'15.'
    version += b'\x00' * (16-len(version))
    date     = b'2015-07-01'
    date    += b'\x00' * (16 -len(date))
    check    = b'\x00\x00\x00\x00'

    header = version + date + check

    data = header + data
    print("[*] WH - Data len: {}".format(len(data)))

    new_check = checksum(data)
    print(f"[*] WH - Checksum: {hex(new_check)}")

    data = data[:0x20] + pack(">I", new_check) + data[0x24:]
    return data
