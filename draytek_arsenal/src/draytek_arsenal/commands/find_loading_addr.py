from draytek_arsenal.commands.base import Command
from typing import Any, Dict, List


from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN


class FindEndiannessCommand(Command):

    @staticmethod
    def name() -> str:
        return "find_loading_addr"

    @staticmethod
    def description() -> str:
        return "Find the address where the RTOS if loaded with the first jump instruction"

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["rtos"], "kwargs": {"type": str, "help": "Path to the rtos"}},
        ]

    @staticmethod
    def execute(args) -> None:
        rtos = args.rtos

        with open(rtos, "rb") as f:
            # Peek 4, tratar de desensamblar y con eso determinar endianness
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
            code = f.read(50 * 4)
            instructions = [i for i in md.disasm(code, 0)]

            if not instructions:
                f.seek(0)
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
                code = f.read(50 * 4)
                instructions = [i for i in md.disasm(code, 0)]

            # Encontrar el primer salto, que es a la funcion que descomprime el kernel
            # Determinar que registro se usa para saltar
            # Calcular el valor de ese registro
            # Redondear a 0x1000 (valor & 0xfffff000)
            mipsEmu = MIPSEmu()
            for i in instructions:
                ins = MIPSInstruction(i)
                if ins.mnemonic() != "jalr":
                    mipsEmu.parseInstruction(ins)
                else:
                    jmpReg = ins.arg(0)
                    jmpAddr = mipsEmu.register(jmpReg)
                    lAddr = jmpAddr & 0xfffff000
                    print("[*] First jump found")
                    print("[*] Kernel decompression function at 0x{:x}".format(jmpAddr))
                    print("[+] Loading address is 0x{:x}".format(lAddr))
                    exit(0)
            print("No jump found...")
            exit(1)



# Modified from https://github.com/infobyte/cve-2022-27255/blob/main/analysis/firmware_base_address_finder.py by Octavio Galland
class MIPSInstruction():
    def __init__(self, capstoneInstruction):
        self.__args = capstoneInstruction.op_str.split(", ")
        self.__mnemonic = capstoneInstruction.mnemonic
    def argCount(self):
        return len(self.__args)
    def arg(self, i):
        assert i < self.argCount()
        return self.__args[i]
    def args(self):
        return self.__args
    def mnemonic(self):
        return self.__mnemonic

class MIPSEmu():
    def __init__(self):
        self.__regs = {
            "$zero":0,
			"$at": 0,
			"$v0": 0,
			"$v1": 0,
			"$a0": 0,
			"$a1": 0,
			"$a2": 0,
			"$a3": 0,
			"$t0": 0,
			"$t1": 0,
			"$t2": 0,
			"$t3": 0,
			"$t4": 0,
			"$t5": 0,
			"$t6": 0,
			"$t7": 0,
			"$s0": 0,
			"$s1": 0,
			"$s2": 0,
			"$s3": 0,
			"$s4": 0,
			"$s5": 0,
			"$s6": 0,
			"$s7": 0,
			"$t8": 0,
			"$t9": 0,
			"$k0": 0,
			"$k1": 0,
			"$gp": 0,
			"$sp": 0,
			"$s8": 0,
			"$ra": 0,
			"$sr": 0,
			"$lo": 0,
			"$hi": 0,
			"$bad": 0,
			"$cause": 0,
			"$pc": 0,
			"$fsr": 0,
			"$fir": 0,
		    "$fp": 0
	}

    def parseInstruction(self, instruction):
        # opcode dstReg, val1, val2
        opcode = instruction.mnemonic()
        if opcode in ["mtc0", "mfc0", "ehb"]:
            # ignore coprocessor related instructions
            return
        if opcode in ["sw", "lw", "bne", "beq", "sync", "ins", "jal", "nop", "j"]:
            # ignore load, store adn branches for now
            return
        if opcode == "move":
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            self.register(dstReg, val1)
            return
        if opcode == "lui":
            dstReg = instruction.arg(0)
            val1 = int(instruction.arg(1), 0)
            self.register(dstReg, val1 << 16)
            return
        if opcode in ["addi", "addiu", "ori", "xori", "andi"]:
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            val2 = int(instruction.arg(2), 0)
            if opcode == "ori":
                self.register(dstReg, (val1 | val2) & 0xffffffff)
            elif opcode == "xori":
                self.register(dstReg, (val1 ^ val2) & 0xffffffff)
            elif opcode == "andi":
                self.register(dstReg, (val1 & val2) & 0xffffffff)
            else:
                self.register(dstReg, (val1 + val2) & 0xffffffff)
            return
        if opcode == "or":
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            val2 = self.register(instruction.arg(2))
            self.register(dstReg, (val1 | val2) & 0xffffffff)
            return
        if opcode == "and":
            dstReg = instruction.arg(0)
            val1 = self.register(instruction.arg(1))
            val2 = self.register(instruction.arg(2))
            self.register(dstReg, (val1 & val2) & 0xffffffff)
            return
        raise Exception("opcode not implemented...")

        
    def register(self, regId, value=None):
        if value:
            assert regId in self.__regs
            self.__regs[regId] = value
        else:
            assert regId in self.__regs
            return self.__regs[regId]
