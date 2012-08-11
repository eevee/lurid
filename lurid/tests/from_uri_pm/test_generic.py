from __future__ import unicode_literals

from lurid.uri import URI

def test_simple():
    foo = URI.parse(b'Foo:opaque#frag')

    # TODO this is testing for the uri subclass
    #print "not " unless ref($foo) eq "URI::_foreign";

    # DEVIATION: lurid canonicalizes the scheme
    assert str(foo) == b'foo:opaque#frag'

    assert foo.scheme == 'foo'
    assert foo.opaque == 'opaque'
    assert foo.fragment == 'frag'
    assert foo.serialize() == 'foo:opaque#frag'

    # Scheme
    foo.scheme = "bar"
    assert str(foo) == b"bar:opaque#frag"

    # TODO unclear if this should work or be allowed or what
    # TODO there's no actual parsing or other checking for the scheme, bleh
    #foo.scheme = ""
    #assert str(foo) == "opaque#frag"

    del foo.scheme
    assert str(foo) == b"opaque#frag"

    foo.scheme = "foo"

    # Opaque stuff
    foo.parse_opaque(b"xxx")
    assert foo.opaque == "xxx"
    assert str(foo) == b"foo:xxx#frag"

    foo.parse_opaque(b"")
    assert foo.opaque == ""
    assert str(foo) == b"foo:#frag"

    # TODO unclear what sort of auto-escaping opaque should do; this is clearly
    # not a parse
    #foo.opaque = " #?/"
    #assert foo.opaque == "%20%23?/"

    del foo.opaque
    assert foo.opaque == ""
    assert str(foo) == b"foo:#frag"

    foo.parse_opaque(b"opaque")

    # Fragments
    assert foo.fragment == "frag"

    foo.fragment = "x"
    assert foo.fragment == "x"
    assert str(foo) == b"foo:opaque#x"

    foo.fragment = ""
    assert foo.fragment == ""
    assert str(foo) == b"foo:opaque#"

    del foo.fragment
    assert foo.fragment == None
    assert str(foo) == b"foo:opaque"


def test_comparison():
    foo = URI.parse(b"foo:opaque")

    # TODO if this is even a thing i want
    #assert foo == "Foo:opaque"
    assert foo == URI.parse(b"FOO:opaque")
    #assert foo == "foo:opaque"

    assert foo != "Bar:opaque"
    assert foo != "foo:opaque#"


def test_hierarchy():
    foo = URI.parse(b"foo://host:80/path?query#frag")

    assert str(foo) == b"foo://host:80/path?query#frag"

    # Accessors
    assert foo.scheme == "foo"
    assert foo.authority == "host:80"
    assert foo.path == "/path"
    assert foo.query == "query"
    assert foo.fragment == "frag"

    # Authority
    foo.parse_authority(b"xxx")
    assert foo.authority == "xxx"
    assert str(foo) == b"foo://xxx/path?query#frag"

    foo.parse_authority(b"")
    assert foo.authority == ""
    assert str(foo) == b"foo:///path?query#frag"

    del foo.authority
    assert foo.authority is None
    assert str(foo) == b"foo:/path?query#frag"

    foo.parse_authority(b"/? #;@&")
    assert foo.authority == "%2F%3F%20%23;@&"
    assert str(foo) == b"foo://%2F%3F%20%23;@&/path?query#frag"

    foo.parse_authority(b"host:80")
    assert foo.authority == "host:80"
    assert str(foo) == b"foo://host:80/path?query#frag"

    # Path
    foo.path = "/foo"
    assert foo.path == "/foo"
    assert str(foo) == b"foo://host:80/foo?query#frag"

    foo.path = "/bar"
    assert foo.path == "/bar"
    assert str(foo) == b"foo://host:80/bar?query#frag"

    foo.path = ""
    assert foo.path == ""
    assert str(foo) == b"foo://host:80?query#frag"

    foo.path = None
    assert foo.path == ""
    assert str(foo) == b"foo://host:80?query#frag"

    # DEVIATION: lurid refuses to magically change relative paths to absolute
    foo.path = "/@;/?#"
    assert foo.path == "/@;/%3F%23"
    assert str(foo) == b"foo://host:80/@;/%3F%23?query#frag"

    foo.path = "/path"
    assert foo.path == "/path"
    assert str(foo) == b"foo://host:80/path?query#frag"

    # Query
    foo.query = "foo"
    assert foo.query == "foo"
    assert str(foo) == b"foo://host:80/path?foo#frag"

    foo.query = ""
    assert foo.query == ""
    assert str(foo) == b"foo://host:80/path?#frag"

    foo.query = None
    assert foo.query == None
    assert str(foo) == b"foo://host:80/path#frag"

    foo.query = "/?&=# "
    assert foo.query == "/?&=%23%20"
    assert str(foo) == b"foo://host:80/path?/?&=%23%20#frag"

    foo.query = "query"
    assert foo.query == "query"
    assert str(foo) == b"foo://host:80/path?query#frag"


def test_buildup():
    foo = URI()
    # DEVIATION: lurid refuses to magically change relative paths to absolute
    foo.path = "/path"
    foo.parse_authority(b"auth")
    assert str(foo) == b"//auth/path"

    # TODO: $foo = URI->new("", "http:");
    foo = URI()
    foo.query = "query"
    foo.parse_authority(b"auth")
    assert str(foo) == b"//auth?query"

    foo.path = "/path"
    assert str(foo) == b"//auth/path?query"

    foo = URI.parse(b"")
    assert foo.path == ""
    foo.path = "foo"
    assert foo.path == "foo"
    assert str(foo) == b"foo"

    foo.path = "bar"
    assert foo.path == "bar"
    assert foo.opaque == "bar"
    assert str(foo) == b"bar"

    foo.parse_opaque(b"foo")
    assert foo.path == "foo"
    assert foo.opaque == "foo"
    assert str(foo) == b"foo"

    foo.path = ""
    assert str(foo) == b""

    assert foo.query == None
    foo.query = "q"
    assert str(foo) == b"?q"
