import struct
import lz4.block

class Lz4():
    """Draytek's modified Lz4 implementation"""
    magic = b"\xaa\x1d\x7f\x50"
    max_decompressed_block_size = 0x10000

    def decompress(self, input, last_block: int | None = None) -> bytes:
        if self.magic != input[:4]:
            print("[LZ4] Bad block magic: 0x{:x}".format(struct.unpack(">I", input[:4])[0]))
        block_offset = 4
        output = b""      
        while block_offset < len(input) and (last_block is None or block_offset != last_block):
            block_data_size = struct.unpack("<I", input[block_offset:block_offset + 4])[0]

            if block_data_size & 0x90000000 > 0:
                print(f"[LZ4] Uncrompressed block")

            if block_data_size > 2 * self.max_decompressed_block_size:
                print(
                    f"[LZ4] Wrong block size: {hex(block_data_size)} at {hex(block_offset)} with {input[block_offset:block_offset + 4]}"
                )
                exit(1)
            block_data_offset = block_offset + 4
            block = input[block_data_offset:block_data_offset+block_data_size]
            try:
                output += lz4.block.decompress(block, uncompressed_size=self.max_decompressed_block_size)
            except Exception as e:
                print(e)
                exit(1)

            block_offset += block_data_size + 4
        return output
    
    def compress(self, input):
        output = self.magic

        i = 0
        for i in range(0,len(input), self.max_decompressed_block_size):
            compressed_block = lz4.block.compress(input[i:i + self.max_decompressed_block_size], store_size=False)
            output += struct.pack("<I", len(compressed_block))
            output += compressed_block
        
        return output
