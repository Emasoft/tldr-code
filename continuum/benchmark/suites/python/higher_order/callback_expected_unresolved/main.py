def callee():
    return "callee"


def apply(fn):
    return fn()


def run():
    return apply(callee)
