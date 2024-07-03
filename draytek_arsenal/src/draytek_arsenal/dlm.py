import struct
from hashlib import md5
from draytek_arsenal.compression import Lz4
from hexdump import hexdump
    
class DLM():
    """Draytek's DLM file format restorer"""
    dlm_signature = 0x12345678
    dlm_header_format = ">IHHHH36sI"
    compression_header_format = ">II16s"

    def __init__(self, key1: bytes, key2: bytes) -> None:
        self._key1 = key1
        self._key2 = key2
    
    def generate_digest(self, k1, k2):
        if len(k2) > 0x41:
            k2 = md5(k2).digest()
        k2 = k2 + b'\x00' * (0x40 - len(k2))
        k2_1 = bytes(a ^ b for a, b in zip(k2, b'\x36' * 0x40))
        k2_2 = bytes(a ^ b for a, b in zip(k2, b'\x5c' * 0x40))
        d1 = md5(k2_1 + k1).digest()
        d2 = md5(k2_2 + d1).digest()
        return d2
    
    def xtea_decrypt(self, v, k, endianness = ">"):
        assert(len(v) == 8)
        assert(len(k) == 16)
        v0 = struct.unpack(endianness + "I", v[0:4])[0]
        v1 = struct.unpack(endianness + "I", v[4:8])[0]
        ks = struct.unpack(endianness + "IIII", k)
        sum = 0xc6ef3720
        delta = 0x61c88647
        while sum != 0:
            # print("sum: 0x{:x}, v0: 0x{:x}, v1: 0x{:x}".format(sum, v0, v1))
            rk = (sum + ks[3 & (sum >> 11)]) & 0xffffffff
            # print("a1_1: 0x{:x}".format(a1_1))
            sum = (sum + delta) & 0xffffffff
            v1 = (v1 - (rk ^ ((v0 >> 5 ^ v0 << 4) + v0) & 0xffffffff)) & 0xffffffff
            v0 = (v0 - ((sum + ks[sum & 3]) & 0xffffffff ^ ((v1 >> 5 ^ v1 << 4) + v1) & 0xffffffff)) & 0xffffffff
        return struct.pack(endianness + "I", v0) + struct.pack(endianness + "I", v1)
    
    def xtea_encrypt(self, v, k, endianness = ">"):
        assert(len(v) == 8)
        assert(len(k) == 16)
        v0 = struct.unpack(endianness + "I", v[0:4])[0]
        v1 = struct.unpack(endianness + "I", v[4:8])[0]
        ks = struct.unpack(endianness + "IIII", k)
        sum = 0x0
        delta = 0x61c88647
        while sum != 0xc6ef3720:
            # print("sum: 0x{:x}, v0: 0x{:x}, v1: 0x{:x}".format(sum, v0, v1))
            v0 = (v0 + ((sum + ks[sum & 3]) & 0xffffffff ^ ((v1 >> 5 ^ v1 << 4) + v1) & 0xffffffff)) & 0xffffffff
            sum = (sum - delta) & 0xffffffff
            if sum < 0:
                sum = ((sum ^ 0xffffffff) + 1) & 0xffffffff
            rk = (sum + ks[3 & (sum >> 11)]) & 0xffffffff
            v1 = (v1 + (rk ^ ((v0 >> 5 ^ v0 << 4) + v0) & 0xffffffff)) & 0xffffffff
            # print("a1_1: 0x{:x}".format(a1_1))
        return struct.pack(endianness + "I", v0) + struct.pack(endianness + "I", v1)
    
    def restore(self, data):
        dlm_header = data[:0x34]
        print("[*] Parsing header")
        size, main_id_0, main_id_1, main_id_2, main_id_3, padding, signature =  struct.unpack(self.dlm_header_format, dlm_header)
        print(f"\tsize: {size}\n\tsignature: {hex(signature)}")

        dlm_data = data[0x34:]
        dlm_data_len = len(dlm_data)
        print(f"\tdata_len: {len(dlm_data)}")

        if main_id_0 != 0:
            print("[x] Main ID 0: 0x{:x}".format(main_id_0))
            exit(1)

        if main_id_2 != 1:
            print("[x] Main ID 2: 0x{:x}".format(main_id_2))

        if main_id_3 != 0xffff:
            print("[x] Main ID 3: 0x{:x}".format(main_id_3))
            exit(1)

        if signature != 0x12345678:
            print("[x] Signature: 0x{:x}".format(signature))
            exit(1)

        if dlm_data_len != size - 0x34:
            print("[x] DLM data length error")
            exit(1)

        print("[*] Generating digest")
        key = self.generate_digest(self._key1, self._key2)

        print("[*] Decrypting data")
        dlm_data_decrypted = b''
        idx = 0
        while dlm_data_len - idx >= 8:
            dlm_data_decrypted += self.xtea_decrypt(dlm_data[idx:idx + 8], key)
            idx += 8
            print(f"[*] Process: {((100 / dlm_data_len) * idx):.1f} of 100.0", end="\r")

        dlm_data_decrypted = dlm_data_decrypted + dlm_data[idx:]
        # Remove padding (xtea decrypts 8 byte blocks and the last one might have padding)
        dlm_data_decrypted = dlm_data_decrypted.rstrip(b"\x00")
        lz4 = Lz4()
        print("[*] Decryption header:")
        hexdump(dlm_data_decrypted[:0x18])
        # Add checks for compression_header size and digest
        print("[*] Decompressing")
        dlm_data_decrypted_decompressed = lz4.decompress(dlm_data_decrypted[0x18:])
        return dlm_data_decrypted_decompressed

    def pack(self, data):
        lz4 = Lz4()
        digest = self.generate_digest(data, self._key2)
        compressed_data = lz4.compress(data)
        compressed_data_len = len(compressed_data)
        # Possible place for IoC
        compression_header = struct.pack(self.compression_header_format, 0, compressed_data_len, digest)
        compressed_data = compression_header + compressed_data
        compressed_data_len = len(compressed_data)
        
        key = self.generate_digest(self._key1, self._key2)
        encrypted_compressed_data = b""
        idx = 0
        while compressed_data_len - idx >= 8:
            encrypted_compressed_data += self.xtea_encrypt(compressed_data[idx:idx + 8], key)
            idx += 8
        encrypted_compressed_data = encrypted_compressed_data + compressed_data[idx:]
        
        size = compressed_data_len + 0x34
        main_id_0 = 0
        main_id_1 = 1
        main_id_2 = 1
        main_id_3 = 0xffff
        # Possible place for IoC
        padding = b"\x00" * 36
        dlm_header = struct.pack(self.dlm_header_format, size, main_id_0, main_id_1, main_id_2, main_id_3, padding, self.dlm_signature)
        dlm = dlm_header + encrypted_compressed_data

        return dlm
