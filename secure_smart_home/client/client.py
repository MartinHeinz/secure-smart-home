import json

import asyncio

import functools


class IoTClient(asyncio.Protocol):

    def __init__(self, data):
        super().__init__()
        self.messages = data

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(b"Hello, I am Client")

    def data_received(self, data):
        print('Server said: {}'.format(data.decode()))

    def connection_lost(self, exc):
        asyncio.get_event_loop().stop()


def main():
    config = json.load(open('../../config.json'))
    loop = asyncio.get_event_loop()
    client_factory = functools.partial(IoTClient, data="data")
    factory_coroutine = loop.create_connection(client_factory, config["ngrok"]["NGROK_TUNNEL_URL"], int(config["ngrok"]["NGROK_CONNECT_PORT"]))
    loop.run_until_complete(factory_coroutine)
    loop.run_forever()
    loop.close()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()




