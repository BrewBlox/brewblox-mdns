"""
Tests brewblox_mdns.__main__
"""

from unittest.mock import call

from asynctest import CoroutineMock

from brewblox_mdns import __main__ as main

TESTED = main.__name__


def test_main(mocker, app):
    mocker.patch(TESTED + '.service.run')
    mocker.patch(TESTED + '.service.create_app').return_value = app
    main.main([])


def test_cli(mocker):
    m_usb = mocker.patch(TESTED + '.print_usb')
    m_wifi = mocker.patch(TESTED + '.print_wifi', CoroutineMock())

    main.main(['--cli'])
    assert m_usb.call_count == 1
    assert m_wifi.call_count == 1


def test_print_usb(mocker):
    entry = 'usb-Particle_P1_4f0052000551353432383931-if00'
    m = mocker.patch(TESTED + '.glob', return_value=[entry]*2)
    m_print = mocker.patch(TESTED + '.print')

    main.print_usb()

    assert m.call_count == 1
    assert m_print.call_args_list == [
        call('usb', '4f0052000551353432383931', 'P1'),
        call('usb', '4f0052000551353432383931', 'P1'),
    ]


async def test_print_wifi(mocker):
    async def discovery_generator(id, type, timeout):
        for i in range(5):
            yield f'addr-{i}', '8332', 'serial-1'

    mocker.patch(TESTED + '.dns_discovery.discover_all', discovery_generator)
    m_print = mocker.patch(TESTED + '.print')

    await main.print_wifi()

    assert m_print.call_args_list == [
        call('wifi', 'serial-1', 'addr-0', '8332'),
        call('wifi', 'serial-1', 'addr-1', '8332'),
        call('wifi', 'serial-1', 'addr-2', '8332'),
        call('wifi', 'serial-1', 'addr-3', '8332'),
        call('wifi', 'serial-1', 'addr-4', '8332'),
    ]
