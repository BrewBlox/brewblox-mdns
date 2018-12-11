"""
Entrypoint for brewblox_mdns
"""

import logging

from brewblox_service import brewblox_logger, service

from brewblox_mdns import dns_discovery

LOGGER = brewblox_logger(__name__)


def main():
    app = service.create_app(default_name='mdns')
    logging.captureWarnings(True)

    dns_discovery.setup(app)

    service.furnish(app)
    service.run(app)


if __name__ == '__main__':
    main()
