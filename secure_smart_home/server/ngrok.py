import json
import os
import re
import time
import urllib.request
import uuid
import logging
import subprocess
from distutils.spawn import find_executable

import xmltodict

logger = logging.getLogger(__name__)

PORT = 5000


class NgrokTunnel:

    def __init__(self, port, auth_token, subdomain_base=""):
        """Initalize Ngrok tunnel.

        :param auth_token: Your auth token string you get after logging into ngrok.com

        :param port: int, localhost port forwarded through tunnel

        :parma subdomain_base: Each new tunnel gets a generated subdomain. This is the prefix used for a random string.
        """
        assert find_executable("ngrok"), "ngrok command must be installed, see https://ngrok.com/"
        self.port = port
        self.auth_token = auth_token
        self.subdomain = "{}-{}".format(subdomain_base, str(uuid.uuid4()))

    def start(self, ngrok_die_check_delay=0.5):
        """Starts the thread on the background and blocks until we get a tunnel URL.

        :return: the tunnel URL which is now publicly open for your localhost port
        """

        logger.debug("Starting ngrok tunnel %s for port %d", self.subdomain, self.port)

        self.ngrok = subprocess.Popen(["ngrok", "tcp", "-log=stdout", str(self.port)], stdout=subprocess.DEVNULL)

        # See that we don't instantly die
        time.sleep(ngrok_die_check_delay)
        assert self.ngrok.poll() is None, "ngrok terminated abrutly"
        with urllib.request.urlopen('http://localhost:4040/api/tunnels') as response:
            data = response.read().decode("utf-8")
            # url = "https://{}.ngrok.com".format(re.findall('public_url\":\"https://(.+)\.ngrok\.io', data)[0])
            port = re.findall('tcp://0\.tcp\.ngrok\.io:(\d+)', data)[0]
            print(port)
        return port

    def stop(self):
        """Tell ngrok to tear down the tunnel.

        Stop the background tunneling process.
        """
        self.ngrok.terminate()


def main():
    config = json.load(open('../../config.json'))
    auth_token = os.environ["NGROK_AUTH_TOKEN"]
    ngrok = NgrokTunnel(PORT, auth_token)
    config["ngrok"]["NGROK_LISTEN_PORT"] = str(PORT)
    config["ngrok"]["NGROK_TUNNEL_URL"] = "0.tcp.ngrok.io"
    config["ngrok"]["NGROK_CONNECT_PORT"] = ngrok.start()
    with open('../../config.json', 'w') as outfile:
        json.dump(config, outfile)


if __name__ == '__main__':
    main()
