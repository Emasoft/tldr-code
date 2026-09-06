
from .mod import Service

def boot():
    s = Service("x")
    s.increment()
    s.label()
    return s
