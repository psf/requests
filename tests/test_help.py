# -*- encoding: utf-8

import sys

import pytest

from requests.help import info


@pytest.mark.skipif(sys.version_info[:2] != (2,6), reason="Only run on Python 2.6")
def test_system_ssl_py26():
    """OPENSSL_VERSION_NUMBER isn't provided in Python 2.6, verify we don't
    blow up in this case.
    """
    assert info()['system_ssl'] == {'version': ''}


@pytest.mark.skipif(sys.version_info < (2,7), reason="Only run on Python 2.7+")
def test_system_ssl():
    """Verify we're actually setting system_ssl when it should be available."""
    assert info()['system_ssl']['version'] != ''


class VersionedPackage(object):
    def __init__(self, version):
        self.__version__ = version


def test_idna_without_version_attribute(mocker):
    """Older versions of IDNA don't provide a __version__ attribute, verify
    that if we have such a package, we don't blow up.
    """
    mocker.patch('requests.help.idna', new=None)
    assert info()['idna'] == {'version': ''}


def test_idna_with_version_attribute(mocker):
    """Verify we're actually setting idna version when it should be available."""
    mocker.patch('requests.help.idna', new=VersionedPackage('2.6'))
    assert info()['idna'] == {'version': '2.6'}
