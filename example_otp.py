# This script selects the EMV-CAP application and sends a VERIFY PIN command to the card.
#
# Generating and encoding an EMV-CAP one-time password can be issuer-specific, and is not included in this file.
#
import getpass
import typing
from typing import Optional, Union

import smartcard.CardConnection
import smartcard.CardRequest  # type: ignore

from pyemv.emv import Emv
from pyemv.iso7816.apdu import CommandApdu, ResponseApdu
from pyemv.iso7816.card import Card
from pyemv.transport import Transport
from pyemv.transport.pyscard import PySCardTransport


def hexlify(x: Optional[Union[bytes, int]]) -> Optional[str]:
    if isinstance(x, int):
        length = (x.bit_length() + 7) // 8
        x = x.to_bytes(max(length, 1), "big")
    if not x:
        return None
    return x.hex().upper()


def debug(prefix: str, *args: Optional[Union[int, bytes]]) -> None:
    strings = list(filter(None, map(hexlify, args)))
    print(" ".join([prefix] + strings))


class DebugTransport(Transport):
    def __init__(self, transport: Transport):
        self.transport = transport

    def transmit(self, command: CommandApdu) -> ResponseApdu:
        data = command.data
        debug(
            ">",
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            data and len(data),
            command.data,
            command.le,
        )
        response = self.transport.transmit(command)
        debug("<", response.data, response.sw)
        return response


def wait_for_card() -> smartcard.CardConnection.CardConnection:
    connection = typing.cast(
        smartcard.CardConnection.CardConnection,
        smartcard.CardRequest.CardRequest()  # type: ignore
        .waitforcard()
        .connection,
    )
    connection.connect()  # type: ignore
    return connection


def main():
    card = Card(DebugTransport(PySCardTransport(wait_for_card())))
    emv = Emv(card)

    # Select the EMV-CAP application
    emv.select_file(b"\xA0\x00\x00\x00\x03\x80\x02")
    emv.verify_plaintext_pin(getpass.getpass("PIN: "))


if __name__ == "__main__":
    main()
