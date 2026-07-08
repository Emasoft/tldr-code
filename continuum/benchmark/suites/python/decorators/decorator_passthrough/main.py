def passthrough(fn):
    return fn


@passthrough
def action():
    return "action"


def run():
    return action()
