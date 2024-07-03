import os
import errno
import struct
from draytek_arsenal.compression import Lz4
from draytek_arsenal.dlm import DLM
            
class PFSCommon(object):
    def _make_short(self, data, endianness):
        """Returns a 2 byte integer."""
        # data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sH' % endianness, data)[0]

    def _make_int(self, data, endianness):
        """Returns a 4 byte integer."""
        # data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sI' % endianness, data)[0]

class PFS(PFSCommon):
    """Class for accessing PFS meta-data."""
    HEADER_SIZE = 16
    def __init__(self, fname, endianness='<'):
        self.endianness = endianness
        self.meta = open(fname, 'rb')
        header = self.meta.read(self.HEADER_SIZE)
        self.file_list_start = self.meta.tell()
        self.dlm_fs = header[:7] == b"DLM/1.0"
        self.num_files = self._make_short(header[-2:], endianness)
        self.node_size = self._get_fname_len() + 12

    def _get_fname_len(self, bufflen=128):
        """Returns the number of bytes designated for the filename."""
        buff = self.meta.peek(bufflen)
        strlen = buff.find(b'\x00')
        for i, b in enumerate(buff[strlen:]):
            if b != 0:
                return strlen+i
        return bufflen

    def _get_node(self):
        """Reads a chunk of meta data from file and returns a PFSNode."""
        data = self.meta.read(self.node_size)
        return PFSNode(data, self.endianness)

    def get_end_of_meta_data(self):
        """Returns integer indicating the end of the file system meta data."""
        return self.HEADER_SIZE + self.node_size * self.num_files

    def entries(self):
        """Returns file meta-data entries one by one."""
        self.meta.seek(self.file_list_start)
        for i in range(0, self.num_files):
            yield self._get_node()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.meta.close()

class PFSNode(PFSCommon):
    """A node in the PFS Filesystem containing meta-data about a single file."""
    def __init__(self, data, endianness):
        self.fname, data = data[:-12], data[-12:]
        self._decode_fname()
        self.inode_no = self._make_int(data[:4], endianness)
        self.foffset = self._make_int(data[4:8], endianness)
        self.fsize = self._make_int(data[8:], endianness)

    def _decode_fname(self):
        """Extracts the actual string from the available bytes."""
        null_pos = self.fname.find(b'\x00')
        if null_pos != -1:
            self.fname = self.fname[:null_pos]
        self.fname = self.fname.replace(b'\\', b'/').decode()

class PFSExtractor():
    """
    Extractor for Draytek PFS File System Formats.
    Adapted from https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/plugins/unpfs.py
    """

    def __init__(self, key1: bytes = b"", key2: bytes = b"") -> None:
        self._key1 = key1
        self._key2 = key2

    def _create_dir_from_fname(self, fname):
        try:
            os.makedirs(os.path.dirname(fname))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e

    def extract(self, fname, out_dir):
        fname = os.path.abspath(fname)
        lz4 = Lz4()
        dlm = DLM(self._key1, self._key2)

        print("[*] Extracting PFS filesystem to: {}".format(out_dir))

        with PFS(fname) as fs:
            # The end of PFS meta data is the start of the actual data
            data = open(fname, 'rb')
            data.seek(fs.get_end_of_meta_data())
            for entry in fs.entries():
                print(f"[*] FS entry found: '{entry.fname}'")
                outfile_path = os.path.abspath(os.path.join(out_dir, entry.fname))

                self._create_dir_from_fname(outfile_path)

                with open(outfile_path, 'wb') as outfile:
                    file_content = data.read(entry.fsize)
                    if fs.dlm_fs:
                        print("[*] Restoring file as DLM")
                        file_content = dlm.restore(file_content)
                    elif lz4.magic == file_content[:4]:
                        file_content = lz4.decompress(file_content)
                    outfile.write(file_content)

            data.close()
        
        return out_dir
