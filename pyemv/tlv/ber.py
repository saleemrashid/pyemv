from typing import BinaryIO, Optional, Type, TypeVar

from pyemv.tlv import TagValueList

_Tag = TypeVar("_Tag", bound="BerTag")
_Length = TypeVar("_Length", bound="BerLength")


class BerTag(object):
    def __init__(self, value: bytes):
        self._value = value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._value!r})"

    def __bytes__(self) -> bytes:
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented  # type: ignore
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    @classmethod
    def decode(cls: Type[_Tag], stream: BinaryIO) -> Optional[_Tag]:
        while True:
            buf = stream.read(1)
            if not len(buf):
                return None
            if buf[0] != 0:
                break

        value = bytearray(buf)

        if value[0] & 0x1F == 0x1F:
            value.extend(readexactly(stream, 1))
            while value[-1] & 0x80 == 0x80:
                value.extend(readexactly(stream, 1))

        return cls(value)


class BerLength(object):
    def __init__(self, value: int):
        self._value = value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._value!r})"

    def __int__(self) -> int:
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented  # type: ignore
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    @classmethod
    def decode(cls: Type[_Length], stream: BinaryIO) -> _Length:
        buf = readexactly(stream, 1)
        if buf[0] & 0x80 != 0x80:
            return cls(buf[0])

        buf = readexactly(stream, buf[0] & 0x7F)
        return cls(int.from_bytes(buf, "big"))


def readexactly(stream: BinaryIO, size: int) -> bytes:
    buf = stream.read(size)
    if len(buf) != size:
        raise ValueError
    return buf
