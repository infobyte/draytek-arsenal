from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List, Tuple
import hashlib
import lief
from enum import Enum, auto
from dataclasses import dataclass
from struct import pack
from pprint import pprint
from os.path import basename


# Mips instructions has 32 bites length and the first 6 are the opcode
CODE_HASH_MASK = 0xfc

PROGBITS = lief.ELF.Section.TYPE.PROGBITS
NOBITS = lief.ELF.Section.TYPE.NOBITS
WRITE = lief.ELF.Section.FLAGS.WRITE
ALLOC = lief.ELF.Section.FLAGS.ALLOC
EXECINSTR = lief.ELF.Section.FLAGS.EXECINSTR
MERGE = lief.ELF.Section.FLAGS.MERGE
STRINGS = lief.ELF.Section.FLAGS.STRINGS


SECTION_LIST_TEMPLATE_HEADER = "dlm_section_info {}_sections[]= {{\n"
SECTION_LIST_TEMPLATE_FOOTER = "};\n"
SECTION_STRUCT_TEMPLATE = "\t{{ {}, {}, {}, {} }},\n"
HASH_STRUCT_TEMPLATE = "dlm_info {}_info = {{ {}, {}, {}, {} }};\n"

@dataclass
class SectionHash:
    name: str
    offset: int
    size: int
    is_code: bool
    hash: str


class SectionType(Enum):
    HASHABLE = auto()
    SKIPPED = auto()
    NOHASHABLE = auto()
    CODE = auto()


class DlmHashCommand(Command):

    @staticmethod
    def name() -> str:
        return "dlm_hash"

    @staticmethod
    def description() -> str:
        return "Get the hash of a DLM"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["dlm"], "kwargs": {"type": str, "help": "Path to the dlm"}},
            {"flags": ["-c"], "kwargs": {"action": "store_true", "help": "Print as .c code"}}
        ]

    @staticmethod
    def check_mask(value: int, mask: lief.ELF.Section.FLAGS) -> bool:
        return value & mask == mask

    @staticmethod
    def get_section_type(section: lief.ELF.Section) -> SectionType:
        s_type = section.type
        s_flags = section.flags

        # Check if it is dynamic data
        if s_type == NOBITS or DlmHashCommand.check_mask(s_flags, WRITE | ALLOC):
            return SectionType.NOHASHABLE

        elif s_type == PROGBITS:
            # Check if it is code
            if DlmHashCommand.check_mask(s_flags, ALLOC | EXECINSTR):
                return SectionType.CODE

            # Check if it is static data
            elif  DlmHashCommand.check_mask(s_flags, MERGE | ALLOC):
                return SectionType.HASHABLE

            elif DlmHashCommand.check_mask(s_flags, ALLOC):
                return SectionType.NOHASHABLE

        return SectionType.SKIPPED

    
    @staticmethod
    def hash(content: bytes, is_code: bool = False) -> str:
        if is_code:
            new_content = b""

            # Iterate over instructions
            for inst_start in range(0, len(content), 4):
                data = (content[inst_start] & CODE_HASH_MASK).to_bytes(1)
                new_content += pack("<c", data)
                new_content += b"\0\0\0"

            content = new_content

        return hashlib.md5(content).hexdigest()

    @staticmethod
    def get_hashes(dlm: str) -> Tuple[List[SectionHash] | None, int]:
        parsed_dlm = lief.parse(dlm)

        if parsed_dlm is None:
            print("[x] Error parsing the DLM")
            return None, 0

        hashes: List[SectionHash] = []
        offset = 0
        total_size = 0

        for section in parsed_dlm.sections:
            is_code = False
            hash: str
            actual_offset = offset

            section_type = DlmHashCommand.get_section_type(section)

            if section_type != SectionType.SKIPPED:
                offset += section.size
                total_size += section.size

                if section_type != SectionType.NOHASHABLE:

                    match section_type:
                        case SectionType.HASHABLE:
                            hash = DlmHashCommand.hash(section.content.tobytes())

                        case SectionType.CODE:
                            is_code = True
                            hash = DlmHashCommand.hash(section.content.tobytes(), is_code=True)

                    hashes.append(
                        SectionHash(
                            section.name,
                            actual_offset,
                            section.size,
                            is_code,
                            hash
                        )
                    )

        return hashes, total_size

    @staticmethod
    def bytes_to_code(hash: str) -> str:
        result = "{"

        for byte_offset in range(0, len(hash), 2):
            result += f"0x{hash[byte_offset: byte_offset + 2]}, "

        result += "}"

        return result

    @staticmethod
    def name_to_code(name: str) -> str:
        result = "{"

        for char in name:
            result += f"\'{char}\', "

        result += "}"

        return result


    @staticmethod
    def generate_code(hashes: List[SectionHash], dlm: str, size: int) -> str:
        dlm_name = basename(dlm)
        var_prefix = dlm_name.split(".")[0]

        result = SECTION_LIST_TEMPLATE_HEADER.format(var_prefix)

        for hash in hashes:
            result += SECTION_STRUCT_TEMPLATE.format(
                hash.offset,
                hash.size,
                1 if hash.is_code else 0,
                DlmHashCommand.bytes_to_code(hash.hash)
            )

        result += SECTION_LIST_TEMPLATE_FOOTER

        result += HASH_STRUCT_TEMPLATE.format(
            var_prefix,
            DlmHashCommand.name_to_code(dlm_name),
            size,
            "(dlm_section_info *)&" + var_prefix + "_sections",
            len(hashes)
        )

        return result

    
    @staticmethod
    def execute(args) -> None:
        dlm = args.dlm

        hashes, size = DlmHashCommand.get_hashes(dlm)

        if hashes is None:
            return

        if args.c:
            print(DlmHashCommand.generate_code(hashes, dlm, size))

        else:
            pprint([h.__dict__ for h in hashes])
