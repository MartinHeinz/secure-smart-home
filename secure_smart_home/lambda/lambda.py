# -*- coding: utf-8 -*-

import logging
import threading
import time
import json
import uuid

import asyncio

# Setup logger
import functools
from collections import namedtuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# namespaces

NAMESPACE_CONTROL = "Alexa.ConnectedHome.Control"
NAMESPACE_DISCOVERY = "Alexa.ConnectedHome.Discovery"

# discovery

REQUEST_DISCOVER = "DiscoverAppliancesRequest"
RESPONSE_DISCOVER = "DiscoverAppliancesResponse"

# control

REQUEST_TURN_ON = "TurnOnRequest"
RESPONSE_TURN_ON = "TurnOnConfirmation"
REQUEST_TURN_OFF = "TurnOffRequest"
RESPONSE_TURN_OFF = "TurnOffConfirmation"

# errors

ERROR_UNSUPPORTED_OPERATION = "UnsupportedOperationError"
ERROR_UNEXPECTED_INFO = "UnexpectedInformationReceivedError"

SAMPLE_ENDPOINT = [
    {
        "endpointId": "endpoint-001",
        "manufacturerName": "Sample Manufacturer",
        "friendlyName": "Light",
        "description": "001 Light that is dimmable and can change color and color temperature",
        "displayCategories": [
            "LIGHT"
        ],
        "cookie": {

        },
        "capabilities": [
            {
                "type": "AlexaInterface",
                "interface": "Alexa.PowerController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "powerState"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.ColorController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "color"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.ColorTemperatureController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "colorTemperatureInKelvin"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.BrightnessController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "brightness"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.PowerLevelController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "powerLevel"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.PercentageController",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "percentage"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            },
            {
                "type": "AlexaInterface",
                "interface": "Alexa.EndpointHealth",
                "version": "3",
                "properties": {
                    "supported": [
                        {
                            "name": "connectivity"
                        }
                    ],
                    "proactivelyReported": True,
                    "retrievable": True
                }
            }
        ]
    }
]

SERVER_ADDRESS = ('0.tcp.ngrok.io', 15316)

PROTOCOL_INFO = b'0'
PROTOCOL_PUBLIC_KEY = b'1'
PROTOCOL_DATA = b'2'
PROTOCOL_DISCONNECT = b'3'


def worker(loop, results, request):
    asyncio.set_event_loop(loop)

    client_factory = functools.partial(LambdaClient, client_id="some-access-token", receiver_id="endpoint-001", results=results)
    factory_coroutine = loop.create_connection(client_factory, *SERVER_ADDRESS)
    loop.run_until_complete(factory_coroutine)
    loop.run_forever()
    loop.close()
    return  # stop worker (Thread)


def lambda_handler(request, context):
    """Main Lambda handler."""

    # if asyncio.get_event_loop().is_closed():
    #     asyncio.set_event_loop(asyncio.new_event_loop())
    # loop = asyncio.get_event_loop()
    # coro = loop.create_connection(LambdaClient, '0.tcp.ngrok.io', 15316)
    # loop.run_until_complete(coro)
    # loop.run_forever()
    # loop.close()

    logger.info("Directive:")
    logger.info(json.dumps(request, indent=4, sort_keys=True))

    version = get_directive_version(request)
    request_name = request["directive"]["header"]["name"]
    response = None
    try:
        if request_name == "Discover":
            response = handle_discovery(request)
        else:
            response = handle_control(request)

    except ValueError as error:
        logger.error(error)
        raise

    worker_loop = asyncio.new_event_loop()
    results = [None]
    t = threading.Thread(target=worker, args=(worker_loop, results, request))
    t.start()
    t.join()

    return response
    # TODO return results[0]


def get_uuid():
    return str(uuid.uuid4())


def create_header(namespace, name):
    header = {
        "messageId": get_uuid(),
        "namespace": namespace,
        "name": name,
        "payloadVersion": "3"
    }
    return header


def create_directive(header, payload):
    directive = {
        "event": {
            "header": header,
            "payload": payload
        }
    }
    return directive


def handle_discovery(request):
    # TODO: function to retrieve device info from device cloud
    endpoints = get_endpoints(request)
    header = create_header("Alexa.Discovery", "Discover.Response")
    payload = {
        "endpoints": endpoints
    }
    return create_directive(header, payload)


def get_endpoints(request):
    access_token = request["directive"]["payload"]["scope"]["token"]
    logger.info("Retrieving devices for user with access token:")
    logger.info(access_token)
    # TODO call device cloud
    endpoints = SAMPLE_ENDPOINT
    return endpoints


def handle_control(request):
    response = None
    request_name = request["directive"]["header"]["name"]
    request_namespace = request["directive"]["header"]["namespace"]
    if request_namespace == "Alexa.PowerController":
        if request_name == "TurnOn":
            response = handle_control_turn_on(request)
        else:
            response = handle_control_turn_off(request)
    elif request_namespace == "Alexa.Authorization":
        if request_name == "AcceptGrant":
            response = handle_control_accept_grant(request)
            return response
    else:
        response = handle_unsupported_operation(request)
        # logger.error(...)

    return response


def handle_control_turn_on(request):
    call_device_cloud(request, "powerState", "ON")
    response = {
        "context": {
            "properties": [
                {
                    "namespace": "Alexa.PowerController",
                    "name": "powerState",
                    "value": "ON",
                    "timeOfSample": get_utc_timestamp(),
                    "uncertaintyInMilliseconds": 500
                }
            ]
        },
        "event": {
            "header": {
                "namespace": "Alexa",
                "name": "Response",
                "payloadVersion": "3",
                "messageId": get_uuid(),
                "correlationToken": request["directive"]["header"]["correlationToken"]
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": "access-token-from-Amazon"
                },
                "endpointId": request["directive"]["endpoint"]["endpointId"]
            },
            "payload": {}
        }
    }

    return response


def handle_control_turn_off(request):
    call_device_cloud(request, "powerState", "OFF")
    response = {
        "context": {
            "properties": [
                {
                    "namespace": "Alexa.PowerController",
                    "name": "powerState",
                    "value": "OFF",
                    "timeOfSample": get_utc_timestamp(),
                    "uncertaintyInMilliseconds": 500
                }
            ]
        },
        "event": {
            "header": {
                "namespace": "Alexa",
                "name": "Response",
                "payloadVersion": "3",
                "messageId": get_uuid(),
                "correlationToken": request["directive"]["header"]["correlationToken"]
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": "access-token-from-Amazon"
                },
                "endpointId": request["directive"]["endpoint"]["endpointId"]
            },
            "payload": {}
        }
    }

    return response


def handle_control_accept_grant(request):
    # TODO call device cloud
    response = {
        "event": {
            "header": {
                "namespace": "Alexa.Authorization",
                "name": "AcceptGrant.Response",
                "payloadVersion": "3",
                "messageId": "5f8a426e-01e4-4cc9-8b79-65f8bd0fd8a4"
            },
            "payload": {}
        }
    }
    return response


def handle_unsupported_operation(request):
    response = {
        "event": {
            "header": {
                "namespace": "Alexa",
                "name": "ErrorResponse",
                "messageId": get_uuid(),
                "correlationToken": request["directive"]["header"]["correlationToken"],
                "payloadVersion": "3"
            },
            "endpoint": {
                "endpointId": request["directive"]["endpoint"]["endpointId"]
            },
            "payload": {
                "type": "NOT_SUPPORTED_IN_CURRENT_MODE",
                "message": ""
            }
        }
    }
    return response


def call_device_cloud(request, command, command_value):
    # TODO call device cloud
    access_token = request["directive"]["endpoint"]["scope"]["token"]
    endpoint_id = request["directive"]["endpoint"]["endpointId"]
    logger.info("Call device cloud to perform {command} with value: {value} on endpoint {endpoint}".format(
        command=command,
        value=command_value,
        endpoint=endpoint_id
    ))


def get_utc_timestamp(seconds=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S.00Z", time.gmtime(seconds))


def get_directive_version(request):
    try:
        return request["directive"]["header"]["payloadVersion"]
    except:
        try:
            return request["header"]["payloadVersion"]
        except:
            return "-1"


Keys = namedtuple("Keys", "public_key, private_key, symmetric_key")


class LambdaClient(asyncio.Protocol):

    def __init__(self, client_id, receiver_id, results):
        super().__init__()
        self.client_id = client_id
        self.receiver_id = receiver_id
        self.results = results
        self.transport = None

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.keys = Keys(public_key, private_key, None)

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(format_message(PROTOCOL_INFO, str.encode(self.__class__.__name__), str.encode(self.client_id)))
        pem = self.keys.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logger.info("Public key:")
        logger.info(pem)
        self.transport.write(format_message(PROTOCOL_PUBLIC_KEY, pem, str.encode(self.receiver_id)))

    def data_received(self, data):
        logger.info(b'Received: ' + data)
        if data.startswith(PROTOCOL_DATA):  # data encrypted with symmetric_key or self.keys.public_key
            data = data.split(str.encode("."), 1)[1]
            enc_data, sender_id = data.rsplit(str.encode("."), 1)
            logger.info("Encrypted data:")
            logger.info(enc_data)
            if self.keys.symmetric_key is None:  # symmetric_key should be inside enc_data
                symmetric_key = self.keys.private_key.decrypt(
                    enc_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                logger.info("Symmetric key received:")
                logger.info(symmetric_key)
                self.keys = Keys(self.keys.public_key, self.keys.private_key, symmetric_key)

                # SENDING DATA FOR TESTING
                cipher_suite = Fernet(self.keys.symmetric_key)
                token = cipher_suite.encrypt(b'some data to be encrypted...')
                self.transport.write(format_message(PROTOCOL_DATA, token, str.encode(self.receiver_id)))

                asyncio.get_event_loop().stop()  # TODO change this

            else:
                cipher_suite = Fernet(self.keys.symmetric_key)
                data = cipher_suite.decrypt(enc_data)
                logger.info("Decrypted data received:")
                logger.info(data)
                asyncio.get_event_loop().stop()  # TODO change this
        else:
            raise Exception("Unknown Message type: {data}".format(data=data.decode()))

        # TODO asyncio.get_event_loop().stop()

    def connection_lost(self, exc):
        logger.info(exc)
        asyncio.get_event_loop().stop()


def format_message(protocol, data, id):
    return str.encode("{protocol}.{data}.{id}".format(
        protocol=protocol.decode(),
        data=data.decode(),
        id=id.decode()
    ))
