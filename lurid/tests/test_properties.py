"""Tests of property access."""

from __future__ import unicode_literals

import pytest

from lurid.uri import InvalidURIError, URI


def test_scheme():
    uri = URI.parse(b'http://foo')

    assert uri.scheme == 'http'

    uri.scheme = 'foo'
    assert uri.scheme == 'foo'
    assert str(uri) == b'foo://foo'

    del uri.scheme
    assert str(uri) == b'//foo'

    uri.scheme = 'HTTP'
    assert str(uri) == 'http://foo'

    # Must use unicode to set properties
    with pytest.raises(TypeError):
        uri.scheme = b'foo'

    # Scheme must be /[a-z][a-z0-9.-+]+/i
    for bad_scheme in ('', '+ssh', 'foo bar', 'http:', 'ftp%20'):
        with pytest.raises(InvalidURIError):
            uri.scheme = bad_scheme


def test_authority():
    uri = URI.parse(b'what://foo:bar@host:/')

    assert uri.userinfo == 'foo:bar'
    assert uri.host == 'host'
    assert uri.port == None
    assert str(uri) == b'what://foo:bar@host/'

    # Play with the userinfo
    # TODO split this into user/password?  seems scheme-specific.
    uri.userinfo = u'hello world'
    assert str(uri) == b'what://hello%20world@host/'
    del uri.userinfo
    assert str(uri) == b'what://host/'

    # Play with the host
    # TODO domain
    # TODO ipv4
    # TODO ipv6
    # TODO no host vs empty host
    # TODO port
    # TODO standard ports


def test_opaque():
    pass


def test_path():
    pass


def test_query():
    pass


def test_fragment():
    uri = URI.parse(b'http://foo#bar')
    assert uri.fragment == 'bar'

    del uri.fragment
    assert str(uri) == b'http://foo'


    uri = URI.parse(b'http://foo#where%20am%20i...')
    assert uri.fragment == 'where am i...'

    uri.fragment = 'right here'
    assert str(uri) == b'http://foo#right%20here'
