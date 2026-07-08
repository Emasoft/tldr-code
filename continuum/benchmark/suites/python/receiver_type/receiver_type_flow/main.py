from factory import Client


def build():
    client = Client()
    client.connect()
    return client
