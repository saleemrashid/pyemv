from pyemv.iso7816.apdu import CommandApdu, ResponseApdu
from pyemv.iso7816.constants import CLA_ISO, INS_GET_RESPONSE, SW1
from pyemv.transport import Transport


class GetResponseCommand(CommandApdu):
    def __init__(self, le: int):
        super().__init__(CLA_ISO, INS_GET_RESPONSE, 0x00, 0x00, None, le)


class Card(object):
    def __init__(self, transport: Transport):
        self.transport = transport

    def exchange(self, command: CommandApdu) -> ResponseApdu:
        data = bytearray()

        while True:
            response = self.transport.transmit(command)
            data.extend(response.data)

            if response.sw1 == SW1.BYTES_REMAINING:
                command = GetResponseCommand(response.sw2)
            elif response.sw1 == SW1.CORRECT_LENGTH:
                command = CommandApdu(
                    command.cla,
                    command.ins,
                    command.p1,
                    command.p2,
                    command.data,
                    response.sw2,
                )
            else:
                break

        return ResponseApdu(bytes(data), response.sw1, response.sw2)
