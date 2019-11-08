from pyemv import CardError
from pyemv.iso7816.constants import SW_INCORRECT_PIN_FFF0


class ApduError(CardError):
    def __init__(self, sw: int):
        self.sw = sw

    def __str__(self) -> str:
        return f"Status: {self.sw:04X}"


def make_apdu_exception(sw: int) -> ApduError:
    if sw & 0xFFF0 == SW_INCORRECT_PIN_FFF0:
        return IncorrectPinError(sw)

    return ApduError(sw)


class IncorrectPinError(ApduError):
    @property
    def retries(self) -> int:
        return self.sw & 0xF

    def __str__(self) -> str:
        return f"Retries left: {self.retries}"
