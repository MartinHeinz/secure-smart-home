import json

import asyncio

import functools


class IoTProtocol(asyncio.Protocol):

    def __init__(self, data):
        super().__init__()
        self.messages = data

    def connection_made(self, transport):
        self.transport = transport
        print(b"Client connected.")

    def data_received(self, data):
        print(b"Client said: " + data)
        self.transport.write(b"Server says hello.")

    def connection_lost(self, exc):
        print(b"Connection lost.")
        self.transport = None


def main():
    config = json.load(open('../../config.json'))
    loop = asyncio.get_event_loop()
    client_factory = functools.partial(IoTProtocol, data="data")
    factory_coroutine = loop.create_server(client_factory, "localhost", int(config["ngrok"]["NGROK_LISTEN_PORT"]))
    server = loop.run_until_complete(factory_coroutine)
    print('serving on {}'.format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("exit")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()


def run():  # len pre skusku testov
    return





