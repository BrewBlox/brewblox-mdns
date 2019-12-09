"""
mDNS discovery of Spark devices
"""

import asyncio
from contextlib import suppress
from socket import AF_INET, inet_ntoa

from aiohttp import web
from aiozeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
from async_timeout import timeout
from brewblox_service import brewblox_logger

BREWBLOX_DNS_TYPE = '_brewblox._tcp.local.'
DEFAULT_TIMEOUT_S = 5

LOGGER = brewblox_logger(__name__)
routes = web.RouteTableDef()


def setup(app: web.Application):
    app.router.add_routes(routes)


async def _discover(id: str, dns_type: str, single: bool):
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
        match = f'{id}.local.'.lower() if id else None

        while True:
            info = await queue.get()
            addr = inet_ntoa(info.address)
            if addr == '0.0.0.0':
                continue  # discard simulators
            if match is None or info.server.lower() == match:
                serial = info.server[:-len('.local.')]
                LOGGER.info(f'Discovered {serial} @ {addr}:{info.port}')
                yield addr, info.port, serial
                if single:
                    return
            else:
                LOGGER.info(f'Discarding {info.name} @ {addr}:{info.port}')
    finally:
        await conf.close()


async def discover_all(id: str, dns_type: str, timeout_v: int):
    with suppress(asyncio.TimeoutError):
        async with timeout(timeout_v):
            async for res in _discover(id, dns_type, False):
                yield res


async def discover_one(id: str, dns_type: str, timeout_v: int = None):
    async with timeout(timeout_v):
        async for res in _discover(id, dns_type, True):
            retv = res
        return retv


@routes.post('/discover')
async def post_discover(request: web.Request) -> web.Response:
    """
    ---
    summary: Discover mDNS services
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
    host, port, id = await discover_one(
        request_args.get('id'),
        request_args.get('dns_type', BREWBLOX_DNS_TYPE)
    )
    return web.json_response({'host': host, 'port': port, 'id': id})


@routes.post('/discover_all')
async def post_discover_all(request: web.Request) -> web.Response:
    """
    ---
    summary: Discover all mDNS services
    tags:
    - mDNS
    operationId: mdns.discover_all
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
                dns_type:
                    type: string
                    required: false
                    example: _brewblox._tcp.local.
                timeout:
                    type: int
                    required: false
                    example: 5
    """
    request_args = await request.json()
    retv = []
    async for res in discover_all(None,
                                  request_args.get('dns_type', BREWBLOX_DNS_TYPE),
                                  request_args.get('timeout', DEFAULT_TIMEOUT_S)):
        host, port, id = res
        retv.append({'host': host, 'port': port, 'id': id})
    return web.json_response(retv)
