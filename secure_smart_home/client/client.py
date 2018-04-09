import json
import asyncio
import functools
from collections import namedtuple

import logging
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

Keys = namedtuple("Keys", "peer_public_key, symmetric_key")

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


class IoTClient(asyncio.Protocol):

    def __init__(self, endpoint_id):
        super().__init__()
        self.endpoint_id = endpoint_id
        self.keys = {}  # dict of OtherClient (LambdaClient id) -> Keys
        self.transport = None

        self.log = logging.getLogger(
            'IoTClient_{}'.format(self.endpoint_id)
        )

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(format_message(PROTOCOL_INFO, str.encode(self.__class__.__name__), str.encode(self.endpoint_id)))

        self.log.debug('Connection Made')

    def data_received(self, data):
        self.log.debug('Received: {}'.format(data.decode()))
        if data.startswith(PROTOCOL_PUBLIC_KEY):
            _, lambda_pem_public_key, sender_id = data.split(str.encode("."))
            key = Fernet.generate_key()
            self.log.debug('Generated Fernet Key: {}'.format(key.decode()))
            lambda_public_key = load_pem_public_key(lambda_pem_public_key, backend=default_backend())
            enc_data = lambda_public_key.encrypt(
                key,  # data being encrypted
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.keys[sender_id] = Keys(lambda_public_key, key)
            enc_message = b''.join([PROTOCOL_DATA, str.encode("."), enc_data, str.encode("."), sender_id])
            self.transport.write(enc_message)
            self.log.debug('Sending Encrypted Message: {}'.format(enc_message))

        elif data.startswith(PROTOCOL_DATA):  # data encrypted with symmetric_key
            _, enc_data, sender_id = data.split(str.encode("."))
            cipher_suite = Fernet(self.keys[sender_id].symmetric_key)
            data = cipher_suite.decrypt(enc_data)
            self.log.debug('Received Data (Decrypted): {}, From: {}'.format(data.decode(), sender_id.decode()))
        elif data.startswith(PROTOCOL_DISCONNECT):
            _, lambda_id = data.split(str.encode("."))
            del self.keys[lambda_id]
            self.log.debug("Removed LambdaClient: {id}".format(id=lambda_id))
        else:
            raise Exception("Unknown Message type: {data}".format(data=data.decode()))

    def connection_lost(self, exc):
        self.log.debug("Connection Lost.")
        self.log.debug(exc)
        self.transport = None
        asyncio.get_event_loop().stop()


def main():
    config = json.load(open('../../config.json'))
    loop = asyncio.get_event_loop()
    client_factory = functools.partial(IoTClient, endpoint_id="endpoint-001")
    factory_coroutine = loop.create_connection(client_factory, config["ngrok"]["NGROK_TUNNEL_URL"], int(config["ngrok"]["NGROK_CONNECT_PORT"]))
    loop.run_until_complete(factory_coroutine)
    loop.run_forever()
    loop.close()


# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()




