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


def format_command_response(command, command_value, success):
    return str.encode("{command}.{command_value}.{success}".format(
        command=command,
        command_value=command_value,
        success=str(success)
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
            data = self.decrypt(enc_data, sender_id)
            self.log.debug('Received Data (Decrypted): {}, From: {}'.format(data.decode(), sender_id.decode()))

            command, value = data.split(str.encode("."))
            if command == b"powerState":

                if value == b"ON":
                    self.send_command_response(command, value, sender_id, self.execute_command(command, value))
                elif value == b"OFF":
                    self.send_command_response(command, value, sender_id, self.execute_command(command, value))
                else:
                    raise Exception("Invalid value: {} for command: ".format(value.decode(), command.decode()))
            else:
                raise Exception("Unknown Command: {}".format(command.decode()))

        elif data.startswith(PROTOCOL_DISCONNECT):
            _, lambda_id = data.split(str.encode("."))
            del self.keys[lambda_id]
            self.log.debug("Removed LambdaClient: {id}".format(id=lambda_id))
        else:
            raise Exception("Unknown Message type: {data}".format(data=data.decode()))

    def connection_lost(self, exc):
        self.log.debug("Connection Lost.")
        self.log.debug(exc)  # TODO Debug this
        self.transport = None
        asyncio.get_event_loop().stop()

    def send_command_response(self, command, value, receiver_id, success):
        self.log.debug("Sending Response for: {} with value: {}".format(command.decode(), value.decode()))
        data = format_command_response(command.decode(), value.decode(), success)
        cipher_text = self.encrypt(data, receiver_id)
        message = format_message(PROTOCOL_DATA, cipher_text, receiver_id)
        self.transport.write(message)

    def execute_command(self, command, value):
        # TODO Actually execute command
        return True

    def encrypt(self, plain_text, receiver_id):
        if self.keys[receiver_id].symmetric_key is None:
            raise Exception("Symmetric Key not available.")
        cipher_suite = Fernet(self.keys[receiver_id].symmetric_key)
        token = cipher_suite.encrypt(plain_text)
        return token

    def decrypt(self, cipher_text, sender_id):
        if self.keys[sender_id].symmetric_key is None:
            raise Exception("Symmetric Key not available.")
        cipher_suite = Fernet(self.keys[sender_id].symmetric_key)
        plain_text = cipher_suite.decrypt(cipher_text)
        return plain_text


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




