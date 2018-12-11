"""
mDNS discovery of Spark devices
"""

import asyncio
from socket import AF_INET, inet_ntoa

from aiohttp import web
from aiozeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
from brewblox_service import brewblox_logger

BREWBLOX_DNS_TYPE = '_brewblox._tcp.local.'

LOGGER = brewblox_logger(__name__)
routes = web.RouteTableDef()


def setup(app: web.Application):
    app.router.add_routes(routes)


async def _discover(id: str, dns_type: str):
    queue = asyncio.Queue()
    conf = Zeroconf(asyncio.get_event_loop(), address_family=[AF_INET])

    async def add_service(service_type, name):
        info = await conf.get_service_info(service_type, name)
        await queue.put(info)

    def sync_change_handler(_, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            asyncio.ensure_future(add_service(service_type, name))

    try:
        ServiceBrowser(conf, dns_type, handlers=[sync_change_handler])
        while True:
            info = await queue.get()
            addr = inet_ntoa(info.address)
            if addr == '0.0.0.0':
                continue  # discard simulators
            if id is None or info.server == f'{id}.local.':
                LOGGER.info(f'Discovered {info.name} @ {addr}:{info.port}')
                return addr, info.port
            else:
                LOGGER.info(f'Discarding {info.name} @ {addr}:{info.port}')
    finally:
        await conf.close()


async def discover(id: str, dns_type: str, timeout: int = 0):
    if timeout:
        return await asyncio.wait_for(_discover(id, dns_type), timeout=timeout)
    else:
        return await _discover(id, dns_type)


@routes.post('/discover')
async def post_discover(request: web.Request) -> web.Response:
    """
    ---
    summary: Discovery mDNS services
    tags:
    - mDNS
    operationId: mdns.discover
    produces:
    - application/json
    parameters:
    -
        in: body
        name: body
        required: true
        schema:
            type: object
            properties:
                id:
                    type: string
                    required: false
                    example: 3f0025000851353532343835
                dns_type:
                    type: string
                    required: false
                    example: _brewblox._tcp.local.
    """
    request_args = await request.json()
    host, port = await discover(
        request_args.get('id'),
        request_args.get('dns_type', BREWBLOX_DNS_TYPE)
    )
    return web.json_response({'host': host, 'port': port})
