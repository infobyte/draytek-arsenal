# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Draytek(KaitaiStruct):
    def __init__(self, has_dlm, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.has_dlm = has_dlm
        self._read()

    def _read(self):
        self.bin = Draytek.BinSection(self._io, self, self._root)
        self.web = Draytek.WebSection(self._io, self, self._root)

    class BinSection(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.header = Draytek.BinHeader(self._io, self, self._root)
            self.bootloader = Draytek.Bootloader(self._io, self, self._root)
            self.rtos = Draytek.Rtos(self._io, self, self._root)
            if self._parent.has_dlm:
                self.dlm = Draytek.Dlm(self._io, self, self._root)

            self.not_checksum = self._io.read_u4be()

        @property
        def checksum(self):
            if hasattr(self, '_m_checksum'):
                return self._m_checksum

            self._m_checksum = (self.not_checksum ^ 4294967295)
            return getattr(self, '_m_checksum', None)


    class Dlm(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(7)
            if not self.magic == b"\x44\x4C\x4D\x2F\x31\x2E\x30":
                raise kaitaistruct.ValidationNotEqualError(b"\x44\x4C\x4D\x2F\x31\x2E\x30", self.magic, self._io, u"/types/dlm/seq/0")
            self.data = self._io.read_bytes((self._parent.header.adj_size - self._io.pos()))


    class Bootloader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = []
            i = 0
            while True:
                _ = self._io.read_u4be()
                self.data.append(_)
                if _ == 2774181210:
                    break
                i += 1


    class Rtos(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.rtos_size = self._io.read_u4be()
            self.data = self._io.read_bytes(self.rtos_size)
            if (self._io.pos() % 4) != 0:
                self.padding = self._io.read_bytes((4 - (self._io.pos() % 4)))



    class U3(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.b12 = self._io.read_u2be()
            self.b3 = self._io.read_u1()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value

            self._m_value = ((self.b12 << 12) | self.b3)
            return getattr(self, '_m_value', None)


    class BinHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.size = self._io.read_u4be()
            self.version_info = self._io.read_u1()
            self.next_section = Draytek.U3(self._io, self, self._root)
            self.rest = self._io.read_bytes(248)

        @property
        def adj_size(self):
            if hasattr(self, '_m_adj_size'):
                return self._m_adj_size

            self._m_adj_size = ((((self.size + 3) >> 2) - 1) << 2)
            return getattr(self, '_m_adj_size', None)

        @property
        def bootloader_version(self):
            if hasattr(self, '_m_bootloader_version'):
                return self._m_bootloader_version

            self._m_bootloader_version = (self.version_info >> 4)
            return getattr(self, '_m_bootloader_version', None)

        @property
        def product_number(self):
            if hasattr(self, '_m_product_number'):
                return self._m_product_number

            self._m_product_number = (self.version_info & 15)
            return getattr(self, '_m_product_number', None)


    class WebSection(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.header = Draytek.WebHeader(self._io, self, self._root)
            self.data = self._io.read_bytes(self.header.next_section)
            self.padding = self._io.read_bytes(((self.header.size - self.header.next_section) - 12))
            self.not_checksum = self._io.read_u4be()

        @property
        def checksum(self):
            if hasattr(self, '_m_checksum'):
                return self._m_checksum

            self._m_checksum = (self.not_checksum ^ 4294967295)
            return getattr(self, '_m_checksum', None)


    class WebHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.size = self._io.read_u4be()
            self.next_section = self._io.read_u4be()

        @property
        def adj_size(self):
            if hasattr(self, '_m_adj_size'):
                return self._m_adj_size

            self._m_adj_size = ((((self.size + 3) >> 2) - 1) << 2)
            return getattr(self, '_m_adj_size', None)



