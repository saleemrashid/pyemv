from typing import Iterator, List, Tuple, TypeVar, Union, overload

_default = TypeVar("_default")
_Tag = TypeVar("_Tag")
_Value = TypeVar("_Value")


class TagValueList(List[Tuple[_Tag, _Value]]):
    __marker = object()

    @overload
    def getone(self, tag: _Tag) -> _Value:
        ...

    @overload
    def getone(self, tag: _Tag, default: _default) -> Union[_Value, _default]:
        ...

    def getone(self, tag: _Tag, default: object = __marker) -> object:
        for value in self.getall(tag):
            return value
        if default is not self.__marker:
            return default
        raise KeyError(tag)

    def getall(self, tag: _Tag) -> Iterator[_Value]:
        for t, v in self:
            if t is tag or t == tag:
                yield v
