from typing import overload


class Formatter:
    @overload
    def render(self, value: int) -> str: ...

    @overload
    def render(self, value: str) -> str: ...

    def render(self, value):
        return str(value)

    def run(self):
        return self.render(1)
