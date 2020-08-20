"""
Entrypoint for brewblox_mdns
"""

import asyncio
import re
from glob import glob

import click

from brewblox_mdns import dns_discovery


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


@click.command()
@click.option('--cli', is_flag=True, help='Triggers CLI mode')
@click.option('--discovery',
              type=click.Choice(['all', 'usb', 'wifi']),
              default='all',
              help='Discovery setting. Use "all" to check both Wifi and USB')
def cli(cli, discovery):
    if discovery in ['all', 'usb']:
        print_usb()

    if discovery in ['all', 'wifi']:
        asyncio.run(print_wifi())


if __name__ == '__main__':
    cli()
