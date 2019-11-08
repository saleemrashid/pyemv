from pyemv.emv.constants import INS
from pyemv.emv.errors import InvalidPinError
from pyemv.iso7816.apdu import CommandApdu
from pyemv.iso7816.constants import CLA_ISO


class SelectCommand(CommandApdu):
    def __init__(self, name: bytes):
        super().__init__(CLA_ISO, INS.SELECT, 0x04, 0x00, name, 0x00)


class VerifyCommand(CommandApdu):
    def __init__(self, p2: int, data: bytes):
        super().__init__(CLA_ISO, INS.VERIFY, 0x00, p2, data, None)


class VerifyPlaintextPinCommand(VerifyCommand):
    def __init__(self, pin: str):
        super().__init__(0x80, self.make_plaintext_block(pin))

    @staticmethod
    def make_plaintext_block(pin: str) -> bytes:
        if not pin.isdigit():
            raise InvalidPinError("Must only contain digits")

        length = len(pin)

        if not 4 <= length <= 12:
            raise InvalidPinError("Length must be between 4 and 12")

        block = bytearray((0x20 | length,))
        block.extend(bytes.fromhex(pin + (14 - length) * "F"))

        return bytes(block)
