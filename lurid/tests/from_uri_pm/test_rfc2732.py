"""Test URIs containing IPv6 addresses."""

from lurid.uri import URI

def test_simple():
    uri = URI.parse("http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html")

    assert str(uri) == "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html"
    assert uri.host == "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"
    assert uri.host_port == "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80"
    assert uri.port == 80

    del uri.port
    assert str(uri) == "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/index.html"
    # TODO not clear if this should include the port even when it doesn't exist
    # in the URI
    #assert uri.host_port == "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80"
    uri.port = 80

    uri.host = 'host'
    assert str(uri) == "http://host:80/index.html"

    uri.host = "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"
    assert str(uri) == "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html"
    uri.host_port = "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:88"
    assert str(uri) == "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:88/index.html"
    uri.host_port = "[::1]:80"
    assert str(uri) == "http://[::1]:80/index.html"
    uri.host = "::1:80"
    assert str(uri) == "http://[::1:80]:80/index.html"
    uri.host = "[::1:80]"
    assert str(uri) == "http://[::1:80]:80/index.html"
    # TODO unclear if i like this behavior
    #uri.host = "[::1]:88"
    #assert str(uri) == "http://[::1]:88/index.html"


def test_ftp():
    uri = URI.parse("ftp://ftp:@[3ffe:2a00:100:7031::1]")
    assert str(uri) == "ftp://ftp:@[3ffe:2a00:100:7031::1]"

    assert uri.port == 21
    assert not uri._port

    assert uri.host == "3ffe:2a00:100:7031::1"
    uri.host = "ftp"
    assert str(uri) == "ftp://ftp:@ftp"


def test_localhost():
    uri = URI.parse("http://[::1]")
    assert uri.host == "::1"
