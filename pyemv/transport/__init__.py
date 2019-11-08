from abc import ABC, abstractmethod

from pyemv.iso7816.apdu import CommandApdu, ResponseApdu


class Transport(ABC):
    @abstractmethod
    def transmit(self, command: CommandApdu) -> ResponseApdu:
        ...
