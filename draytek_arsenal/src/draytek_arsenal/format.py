from draytek_arsenal.linux import DraytekLinux
from draytek_arsenal.draytek_format import Draytek
from kaitaistruct import KaitaiStream
from io import BytesIO


def parse_firmware(filename: str,) -> Draytek | DraytekLinux:
    f = open(filename, 'rb')
    data = f.read()

    if b"nonce" in data and b"enc_Image" in data:
        return DraytekLinux(data)

    has_dlm = b"DLM/1.0" in data

    try:
        return Draytek(has_dlm, KaitaiStream(BytesIO(data)))

    except Exception:
        # close file descriptor, then reraise the exception
        f.close()
        raise
