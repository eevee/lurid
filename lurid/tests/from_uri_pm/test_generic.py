from lurid.uri import URI

def test_simple():
    foo = URI('Foo:opaque#frag')

    # TODO this is testing for the uri subclass
    #print "not " unless ref($foo) eq "URI::_foreign";

    assert str(foo) == 'Foo:opaque#frag'

    assert foo.raw_scheme == 'Foo'
    assert foo.scheme == 'foo'
    assert foo.opaque == 'opaque'
    assert foo.fragment == 'frag'
    assert foo.canonical == 'foo:opaque#frag'

    # Scheme
    foo.scheme = "bar"
    assert str(foo) == "bar:opaque#frag"

    # TODO unclear if this should work or be allowed or what
    # TODO there's no actual parsing or other checking for the scheme, bleh
    #foo.scheme = ""
    #assert str(foo) == "opaque#frag"

    foo.scheme = None
    assert str(foo) == "opaque#frag"

    foo.scheme = "foo"

    # Opaque stuff
    foo.opaque = "xxx"
    assert foo.opaque == "xxx"
    assert str(foo) == "foo:xxx#frag"

    foo.opaque = ""
    assert foo.opaque == ""
    assert str(foo) == "foo:#frag"

    foo.opaque = " #?/"
    assert foo.opaque == "%20%23?/"

    foo.opaque = None
    assert foo.opaque == ""
    assert str(foo) == "foo:#frag"

    foo.opaque = "opaque"

    # Fragments
    assert foo.fragment == "frag"

    foo.fragment = "x"
    assert foo.fragment == "x"
    assert str(foo) == "foo:opaque#x"

    foo.fragment = ""
    assert foo.fragment == ""
    assert str(foo) == "foo:opaque#"

    foo.fragment = None
    assert foo.fragment == None
    assert str(foo) == "foo:opaque"


def test_comparison():
    foo = URI("foo:opaque")

    assert foo == "Foo:opaque"
    assert foo == URI("FOO:opaque")
    assert foo == "foo:opaque"

    assert foo != "Bar:opaque"
    assert foo != "foo:opaque#"


def test_hierarchy():
    foo = URI("foo://host:80/path?query#frag")

    assert str(foo) == "foo://host:80/path?query#frag"

    # Accessors
    assert foo.scheme == "foo"
    assert foo.authority == "host:80"
    assert foo.path == "/path"
    assert foo.query == "query"
    assert foo.fragment == "frag"

    # Authority
    foo.authority = "xxx"
    assert foo.authority == "xxx"
    assert str(foo) == "foo://xxx/path?query#frag"

    foo.authority = ""
    assert foo.authority == ""
    assert str(foo) == "foo:///path?query#frag"

    foo.authority = None
    assert foo.authority is None
    assert str(foo) == "foo:/path?query#frag"

    foo.authority = "/? #;@&"
    assert foo.authority == "%2F%3F%20%23;@&"
    assert str(foo) == "foo://%2F%3F%20%23;@&/path?query#frag"

    foo.authority = "host:80"
    assert foo.authority == "host:80"
    assert str(foo) == "foo://host:80/path?query#frag"

    # Path
    foo.path = "/foo"
    assert foo.path == "/foo"
    assert str(foo) == "foo://host:80/foo?query#frag"

    foo.path = "/bar"
    assert foo.path == "/bar"
    assert str(foo) == "foo://host:80/bar?query#frag"

    foo.path = ""
    assert foo.path == ""
    assert str(foo) == "foo://host:80?query#frag"

    foo.path = None
    assert foo.path == ""
    assert str(foo) == "foo://host:80?query#frag"

    foo.path = "@;/?#"
    assert foo.path == "/@;/%3F%23"
    assert str(foo) == "foo://host:80/@;/%3F%23?query#frag"

    foo.path = "path"
    assert foo.path == "/path"
    assert str(foo) == "foo://host:80/path?query#frag"

    # Query
    foo.query = "foo"
    assert foo.query == "foo"
    assert str(foo) == "foo://host:80/path?foo#frag"

    foo.query = ""
    assert foo.query == ""
    assert str(foo) == "foo://host:80/path?#frag"

    foo.query = None
    assert foo.query == None
    assert str(foo) == "foo://host:80/path#frag"

    foo.query = "/?&=# "
    assert foo.query == "/?&=%23%20"
    assert str(foo) == "foo://host:80/path?/?&=%23%20#frag"

    foo.query = "query"
    assert foo.query == "query"
    assert str(foo) == "foo://host:80/path?query#frag"


def test_buildup():
    foo = URI()
    foo.path = "path"
    foo.authority = "auth"
    assert str(foo) == "//auth/path"

    # TODO: $foo = URI->new("", "http:");
    foo = URI()
    foo.query = "query"
    foo.authority = "auth"
    assert str(foo) == "//auth?query"

    foo.path = "path"
    assert str(foo) == "//auth/path?query"

    foo = URI("")
    assert foo.path == ""
    foo.path = "foo"
    assert foo.path == "foo"
    assert str(foo) == "foo"

    foo.path = "bar"
    assert foo.path == "bar"
    assert foo.opaque == "bar"
    assert str(foo) == "bar"

    foo.opaque = "foo"
    assert foo.path == "foo"
    assert foo.opaque == "foo"
    assert str(foo) == "foo"

    foo.path = ""
    assert str(foo) == ""

    assert foo.query == None
    foo.query = "q"
    assert str(foo) == "?q"
