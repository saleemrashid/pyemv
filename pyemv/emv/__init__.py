from pyemv.emv.commands import SelectCommand, VerifyPlaintextPinCommand
from pyemv.iso7816.apdu import ResponseApdu
from pyemv.iso7816.card import Card


class Emv(object):
    def __init__(self, card: Card):
        self.card = card

    def select_file(self, name: bytes) -> ResponseApdu:
        response = self.card.exchange(SelectCommand(name))
        response.check()

        return response

    def verify_plaintext_pin(self, pin: str) -> None:
        response = self.card.exchange(VerifyPlaintextPinCommand(pin))
        response.check()
