"""
Entrypoint for brewblox_mdns
"""

import asyncio
import logging
import re
import sys
from contextlib import suppress
from glob import glob

from brewblox_service import brewblox_logger, service

from brewblox_mdns import dns_discovery

LOGGER = brewblox_logger(__name__)


def print_usb():
    lines = '\n'.join([f for f in glob('/dev/serial/by-id/*')])
    for obj in re.finditer(r'particle_(?P<model>p1|photon)_(?P<serial>[a-z0-9]+)-',
                           lines,
                           re.IGNORECASE | re.MULTILINE):
        print('usb', obj.group('serial'), obj.group('model'))


async def print_wifi():
    async for res in dns_discovery.discover_all(None,
                                                dns_discovery.BREWBLOX_DNS_TYPE,
                                                dns_discovery.DEFAULT_TIMEOUT_S):
        host, port, serial = res
        print('wifi', serial, host, port)


def main(args=sys.argv):
    if '--cli' in args:
        with suppress(KeyboardInterrupt):
            print_usb()
            asyncio.run(print_wifi())
        return

    app = service.create_app(default_name='mdns')
    logging.captureWarnings(True)

    dns_discovery.setup(app)

    service.furnish(app)
    service.run(app)


if __name__ == '__main__':
    main()
