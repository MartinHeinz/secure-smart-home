import json
import asyncio
import logging

import sys

logging.basicConfig(
    level=logging.DEBUG,
    format='%(name)s: %(message)s',
    stream=sys.stderr,
)
log = logging.getLogger('main')

PROTOCOL_INFO = b'0'
PROTOCOL_PUBLIC_KEY = b'1'
PROTOCOL_DATA = b'2'
PROTOCOL_DISCONNECT = b'3'


def format_message(protocol, data, id):
    return str.encode("{protocol}.{data}.{id}".format(
        protocol=protocol.decode(),
        data=data.decode(),
        id=id.decode()
    ))


class IoTProtocol(asyncio.Protocol):

    def __init__(self, factory):
        super().__init__()
        self.factory = factory
        self.address = None
        self.transport = None
        self.type = None
        self.id = None
        self.peer = None

    def connection_made(self, transport):
        self.transport = transport
        self.address = transport.get_extra_info("peername")
        log.debug("Client connected")

    def data_received(self, data):
        if data.startswith(PROTOCOL_INFO):
            _, client_type, client_id = data.split(str.encode("."))

            self.log = logging.getLogger(
                'IoTProtocol_{}_{}'.format(client_id.decode(), client_type.decode()))
            self.log.debug('Information Received')

            self.type = client_type
            self.id = client_id
            if client_type == b"IoTClient":
                self.factory.iot_clients[client_id] = self.transport
            elif client_type == b"LambdaClient":
                self.factory.lambda_clients[client_id] = self.transport
            else:
                raise Exception("Unknown Client type: {type}".format(type=client_type.decode()))
        elif data.startswith(PROTOCOL_PUBLIC_KEY):
            _, client_key, receiver_id = data.split(str.encode("."))
            if self.type == b"LambdaClient":
                self.peer = receiver_id
            receiver = self.factory.iot_clients[receiver_id] if self.type == b"LambdaClient" else self.factory.lambda_clients[receiver_id]
            self.send_data(format_message(PROTOCOL_PUBLIC_KEY, client_key, self.id), receiver)

        elif data.startswith(PROTOCOL_DATA):
            data = data.split(str.encode("."), 1)[1]
            client_data, receiver_id = data.rsplit(str.encode("."), 1)
            receiver = self.factory.iot_clients[receiver_id] if self.type == b"LambdaClient" else self.factory.lambda_clients[receiver_id]
            message = b''.join([PROTOCOL_DATA, str.encode("."), client_data, str.encode("."), self.id])
            self.send_data(message, receiver)

        else:
            raise Exception("Unknown Message type: {data}".format(data=data))

    def send_data(self, data, receiver):
        receiver.write(data)

    def connection_lost(self, exc):
        # self.log.debug("Connection lost")
        if self.type == b"IoTClient":  # TODO WTF IS GOING ON HERE (KEYERROR)
            del self.factory.iot_clients[self.id]
        else:
            del self.factory.lambda_clients[self.id]
            self.factory.iot_clients[self.peer].write(str.encode("{protocol}.{id}".format(protocol=PROTOCOL_DISCONNECT.decode(), id=self.id.decode())))

        self.transport = None


class IoTFactory:

    protocol = IoTProtocol

    def __init__(self):
        self.iot_clients = {}  # {id -> self.transport}
        self.lambda_clients = {}  # {namedtuple(id, timestamp) -> self.transport} # TODO pridat lambde ako ID aj timestamp, keby nahodou prisli od lambdy 2 requesty s rovnakym access tokenom

    def build_protocol(self):
        return self.protocol(self)


def main():
    config = json.load(open('../../config.json'))
    loop = asyncio.get_event_loop()
    # server_factory = functools.partial(IoTProtocol, data="data")
    server_factory = IoTFactory()
    factory_coroutine = loop.create_server(server_factory.build_protocol, "localhost", int(config["ngrok"]["NGROK_LISTEN_PORT"]))
    server = loop.run_until_complete(factory_coroutine)
    log.debug('serving on {}'.format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.debug("exit")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()


def run():  # len pre skusku testov
    return





