from typing import List, Tuple

class CardConnection:
    def transmit(self, buf: List[int]) -> Tuple[List[int], int, int]: ...
