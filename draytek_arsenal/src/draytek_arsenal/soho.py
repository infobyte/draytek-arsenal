import struct


class DraytekSoho:
    def __init__(self, data: bytes) -> None:
        self._data = data

        self.nonce: bytes
        self.image_start: int
        self.image_end: int


        nonce_magic = data.find(b"nonce")
        if nonce_magic == -1:
            raise AttributeError("[x] Couldn't find the 'nonce' magic")
        
        self.nonce = data[nonce_magic + 9: nonce_magic + 9 + 0xC]

        image_magic = data.find(b"enc_Image")
        if image_magic == -1:
            raise AttributeError("[x] Couldn't find the 'enc_Image' magic")

        len_offset = image_magic + 9
        self.image_start = image_magic + 13
        self.image_len = struct.unpack("<I", data[len_offset: len_offset + 4])[0]

    @property
    def data(self):
        return self._data[self.image_start: self.image_start + self.image_len]

    @property
    def header(self):
        return self.data[:self.image_start - 9]
