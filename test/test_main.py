"""
Tests brewblox_mdns.__main__
"""

from brewblox_mdns import __main__ as main

TESTED = main.__name__


def test_main(mocker, app):
    mocker.patch(TESTED + '.service.run')
    mocker.patch(TESTED + '.service.create_app').return_value = app
    main.main()
