import smartcard.CardConnection

from pyemv.iso7816.apdu import CommandApdu, ResponseApdu
from pyemv.transport import Transport


class PySCardTransport(Transport):
    def __init__(self, connection: smartcard.CardConnection.CardConnection):
        self.connection = connection

    def transmit(self, command: CommandApdu) -> ResponseApdu:
        apdu = command.encode()
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        return ResponseApdu(bytes(data), sw1, sw2)
