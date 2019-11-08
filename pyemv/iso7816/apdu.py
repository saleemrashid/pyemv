from dataclasses import dataclass
from typing import Optional

from pyemv.iso7816.constants import SW
from pyemv.iso7816.errors import make_apdu_exception


@dataclass
class CommandApdu(object):
    cla: int
    ins: int
    p1: int
    p2: int
    data: Optional[bytes]
    le: Optional[int]

    def encode(self) -> bytes:
        apdu = bytearray((self.cla, self.ins, self.p1, self.p2))

        if self.data:
            apdu.append(len(self.data))
            apdu.extend(self.data)

        if self.le is not None:
            apdu.append(self.le)

        return bytes(apdu)


@dataclass
class ResponseApdu(object):
    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        return self.sw1 << 8 | self.sw2

    def check(self) -> None:
        if self.sw != SW.NO_ERROR:
            raise make_apdu_exception(self.sw)
