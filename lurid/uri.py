import re
import string
import urllib

# TODO use explicit u or b everywhere in here

class InvalidURIError(ValueError): pass

# TODO unicodes
class RegexGrammar(object):
    # TODO support some backtracking to figure out why matches *fail*.  would
    # require keeping all the pieces separate and repeating a match on failure
    # to see where it goes wrong?
    # TODO actually, short of illegal characters, IS there any string that's
    # not a valid URI?

    def __init__(self):
        self._patterns = {}
        self.rules = {}
        self.charclasses = {}

    def rule(self, name, pattern):
        pattern = '(?:' + pattern.format(**self._patterns) + ')'
        self._patterns[name] = pattern
        self.rules[name] = re.compile(pattern, re.VERBOSE)

    def charclass(self, name, letters):
        self.charclasses[name] = letters
        pattern = '[' + re.escape(letters) + ']'
        self._patterns[name] = pattern
        self.rules[name] = re.compile(pattern)


    def token(self, name, pattern):
        """Just like `rule`, but the regex is wrapped with a (?P<...>) block.

        Only use this on parts that can only appear once in the entire grammar!
        """
        pattern = '(?P<' + name + '>' + pattern.format(**self._patterns) + ')'
        #pattern = '(' + pattern.format(**self._patterns) + ')'
        self._patterns[name] = pattern
        self.rules[name] = re.compile(pattern, re.VERBOSE)

    def find(self, name, string):
        m = self.rules[name].search(string)
        if m:
            return m.groupdict()
        else:
            return None

    def match(self, name, string):
        """Like `find`, but requires the pattern to match the entire string,
        from beginning to end.
        """
        m = self.rules[name].match(string)
        if m and m.end() == len(string):
            return m.groupdict()
        else:
            return None


# This is converted from the BNF reference at the bottom of RFC 3986, URI
# Generic Syntax: http://tools.ietf.org/html/rfc3986
uri_grammar = RegexGrammar()

# Character groups
uri_grammar.charclass('ALPHA', string.ascii_letters)
uri_grammar.charclass('DIGIT', string.digits)
uri_grammar.charclass('HEXDIG', string.hexdigits)
uri_grammar.charclass('sub-delims', "!$&'()*+,;=")
uri_grammar.charclass('gen-delims', "[]:/?#@")
uri_grammar.charclass('reserved', uri_grammar.charclasses['sub-delims'] + uri_grammar.charclasses['gen-delims'])
uri_grammar.charclass('unreserved', string.ascii_letters + string.digits + "-._~")

uri_grammar.rule('pct-encoded', r"% {HEXDIG} {HEXDIG}")
#uri_grammar.rule('pchar', r"{unreserved} | {pct-encoded} | {sub-delims} | [:@]")
uri_grammar.rule('pchar', r"[-._~a-zA-Z0-9:@!$&'()*+,;=] | {pct-encoded}")

uri_grammar.token('query', r"(?: {pchar} | [/?] )*")
uri_grammar.token('fragment', r"(?: {pchar} | [/?] )*")


### IP addresses

# 0-9, 10-99, 100-199, 200-249, or 250-255
uri_grammar.rule('dec-octet', r"{DIGIT} | [1-9] {DIGIT} | [1] {DIGIT} {DIGIT} | [2] [0-4] {DIGIT} | [2] [5] [0-5]")
uri_grammar.rule('IPv4address', r"{dec-octet} [.] {dec-octet} [.] {dec-octet} [.] {dec-octet}")

uri_grammar.rule('h16', r"{HEXDIG}{{1,4}}")
uri_grammar.rule('ls32', r"{h16} [:] {h16} | {IPv4address}")
uri_grammar.token('IPv6address', r"""
                                               (?: {h16} [:] ){{6}} {ls32}
    |                                   [:][:] (?: {h16} [:] ){{5}} {ls32}
    | (?:                      {h16} )? [:][:] (?: {h16} [:] ){{4}} {ls32}
    | (?: ( {h16} [:] ){{0,1}} {h16} )? [:][:] (?: {h16} [:] ){{3}} {ls32}
    | (?: ( {h16} [:] ){{0,2}} {h16} )? [:][:] (?: {h16} [:] ){{2}} {ls32}
    | (?: ( {h16} [:] ){{0,3}} {h16} )? [:][:]     {h16} [:]        {ls32}
    | (?: ( {h16} [:] ){{0,4}} {h16} )? [:][:]                      {ls32}
    | (?: ( {h16} [:] ){{0,5}} {h16} )? [:][:]                      {h16}
    | (?: ( {h16} [:] ){{0,6}} {h16} )? [:][:]
""")


### Authority
uri_grammar.token('IPvFuture', r"[v] {HEXDIG}+ [.] (?: {unreserved} | {sub-delims} | [:] )+")
uri_grammar.token('IP_literal', r"[[] (?: {IPv6address} | {IPvFuture} ) []]")
uri_grammar.token('reg_name', r"(?: {unreserved} | {pct-encoded} | {sub-delims} )*")
uri_grammar.token('host', r"{IP_literal} | {IPv4address} | {reg_name}")

uri_grammar.token('port', r"{DIGIT}*")
uri_grammar.token('userinfo', r"(?: {unreserved} | {pct-encoded} | {sub-delims} | [:] )*")
uri_grammar.token('authority', r"(?: {userinfo} [@] )?  {host}  (?: [:] {port} )?")

### Path, slash opaque part
uri_grammar.rule('segment', r"{pchar}*")
uri_grammar.rule('segment-nz', r"{pchar}+")
# non-zero, no colon
#uri_grammar.rule('segment-nz-nc', r"(?: {unreserved} | {pct-encoded} | {sub-delims} | [@] )+")
uri_grammar.rule('segment-nz-nc', r"(?: [-._~a-zA-Z0-9@!$&'()*+,;=] | {pct-encoded} )+")

uri_grammar.token('path_abempty', r"(?: [/] {segment} )*")
uri_grammar.token('path_absolute', r"[/] (?: {segment-nz} (?: [/] {segment} )* )?")
uri_grammar.token('path_noscheme', r"{segment-nz-nc} (?: [/] {segment} )*")
uri_grammar.token('path_rootless', r"{segment-nz} (?: [/] {segment} )*")
uri_grammar.token('path_empty', r"")


### Entire URI
uri_grammar.token('scheme', r"{ALPHA} (?: {ALPHA} | {DIGIT} | [-+.] )*")

uri_grammar.token('relative_part', r"[/][/] {authority} {path_abempty} | {path_absolute} | {path_noscheme} | {path_empty}")
uri_grammar.rule('relative-ref', r"{relative_part} (?: [?] {query} )? (?: [#] {fragment} )?")

uri_grammar.token('hier_part', r"[/][/] {authority} {path_abempty} | {path_absolute} | {path_rootless} | {path_empty}")
uri_grammar.rule('URI', r"{scheme} [:] {hier_part} (?: [?] {query} )? (?: [#] {fragment} )?")

# I invented this, but it's just relative-ref without a fragment
uri_grammar.rule('relative-opaque', r"{relative_part} (?: [?] {query} )?")


# Unused BNF rules
# All forms of path; never actually used within URI syntax
#uri_grammar.token('path', r"{path_abempty} | {path_absolute} | {path_noscheme} | {path_rootless} | {path_empty}")

# Absolute URI /without/ a fragment allowed.  Main use seems to be for base
# URIs for resolving relative URIs against; the base URI can't have a fragment.
#uri_grammar.rule('absolute-URI', r"{scheme} [:] {hier_part} (?: [?] {query} )?")

# Ultimate rule, matching one of two possibilities.  Not a real rule because it
# duplicates a bunch of tokens, which is illegal in a regex
#uri_grammar.rule('URI-reference', r"{URI} | {relative-ref}")

#{'IPv6address': None, 'IP_literal': None, 'fragment': 'frag', 'IPvFuture': None, 'reg_name': 'host', 'hier_part': '//host:80/path', 'path_rootless': None, 'host': 'host', 'path_abempty': '/path', 'authority': 'host:80', 'path_absolute': None, 'query': 'query', 'path_empty': None, 'scheme': 'foo', 'port': '80', 'userinfo': None}


_default_ports = dict(
    ftp=21,
    http=80,
    https=443,
    ssh=22,
)

def _require_type(value, type_):
    """Oh nooo, type-checking!

    Due to the fiddly nature of URIs and Python 2's handwavey behavior with
    bytes vs unicode, quite a few `URI` methods expect to get only ONE of
    either bytes or unicode.  This function enforces that.
    """
    if not isinstance(value, type_):
        raise TypeError("Expected {0}, got {1!r}".format(
            type_.__name__, value))


def _assemble(*parts):
    # TODO docs
    # TODO this is just not flexible enough; there's no way to specify reserved
    # chars for each particular part
    buf = []
    for part in parts:
        before, middle, after = part
        if middle is not None:
            buf.extend(part)

    return ''.join(buf)




class URI(object):
    """Represents a parsed and mutable URI.  Attempts to follow RFC 3986, with
    some concessions made for the real world.

    A URI consists of a hierarchy of components, as follows:

        - scheme
        - opaque
            - authority
                - userinfo
                    - username
                    - password
                - host
                    - hostname
                    - OR ipv4
                    - OR ipv6
                - port
            - path
                - params
            - query
                - mapping
        - fragment

    Some, all, or none of these may be present in any given URI.  The terms
    "relative" and "absolute" are often used to describe URIs with some of
    these components missing or present, but the terms are somewhat vague:

    * A URI without a scheme is _scheme-relative_.
    * A URI without an authority is _host-relative_.
    * A URI whose path does not begin with a slash is _path-relative_.

    This yields several categories of URIs.

        scheme://userinfo@authority:port/path?query#fragment
        scheme:opaque#fragment
        scheme://authority/abs_path?query#fragment
        scheme:/abs_path?query#fragment
        //authority/abs_path?query#fragment
        /abs_path?query#fragment
        rel_path?query#fragment

    URI components may be reassigned by simple property assignment:

        uri = URI.parse('http://www.google.com/')
        uri.scheme = u'ftp'
        print uri
        # ftp://www.google.com/

    Note that components must be assigned unicode strings, never byte strings.

    Compound components, such as `authority`, cannot be assigned to directly,
    as this is somewhat ambiguous: should the assigned value be considered
    already escaped, or is it a raw substring of another URI?  Instead, you can
    use a `parse_*` method:

        uri = URI.parse('http://www.google.com/')
        uri.parse_authority('www.python.org')
        print uri
        # http://www.python.org/

    As an alternative here, you can just assign to `userinfo, `host`, and
    `port` directly.  The path and query support more fine-grained mutation;
    see the documentation for the `path` and `query` properties.

    Deleting `authority`, `path`, or `query` is supported.
    """

    # TODO figure out what of the above actually belongs in the docstring and
    # what should go elsewhere; module docstring?

    # TODO does it even make sense to have `authority` as an accessor?  does it
    # return something escaped or not?  fuck.  applies to `opaque`, too, and
    # the question was raised by `path` and `query`

    # Based on the RFC's example regex, in appendix B.
    # This will match any arbitrary string, with potentially nonsensical
    # results -- but that's a good thing, so the level of strictness can be
    # controlled.
    simple_uri_rx = re.compile(ur"""\A
        (?P<_scheme>
            (?P<scheme> [^:/?#]+ ):
        )?
        (?P<_authority>
            // (?P<authority> [^/?#]* )
        )?
        (?P<_path_thing> [^?#]* )
        (?P<_query>
            [?] (?P<query> [^#]* )
        )?
        (?P<_fragment>
            [#] (?P<fragment> .* )
        )?
    \Z""", re.VERBOSE)

    # NOTE: the general idea here is to do a very high-level parse, then
    # delegate to property setters that figure the rest out, and so on.  so
    # __init__ just figures out the opaque part, then the opaque setter figures
    # out the authority, then the authority setter figures out the host...
    # TODO turn that comment into a docstring
    # TODO figure out what "strict" means and how it relates to automatic escaping
    # TODO frozen uris -- could even be lazy and only store the string?

    # Defaults, and documentation for the attributes
    # TODO more of these
    _scheme = None
    _userinfo = None
    _host = None
    _host_is_ipv6 = False
    _port = None
    _path = ()
    _query = None
    _fragment = None


    def __init__(self, strict=True, encoding='utf8'):
        """Creates an empty URI.

        If you want to parse a string, see `URI.parse`.
        """

        self.strict = strict
        self._encoding = encoding

    @classmethod
    def parse(cls, string, encoding='utf8'):
        _require_type(string, str)


        self = cls(encoding='utf8')

        # scheme:opaque#fragment
        match = cls.simple_uri_rx.match(string)
        if not match:
            raise IMPOSSIBLE

        matchdict = match.groupdict()

        # Scheme is dead simple: no parts, no percent-escaping allowed.  It's
        # also case-insensitive, so lowercase it to normalize
        if matchdict['scheme'] is not None:
            self.scheme = matchdict['scheme'].decode(encoding).lower()

        # Authority needs some bonus parsing, conveniently done by the
        # authority setter
        if matchdict['authority'] is not None:
            self.parse_authority(matchdict['authority'])

        # Path may need munging...
        self.parse_path(matchdict['_path_thing'])

        # Query needs splitting
        self._query = matchdict['query']

        # Fragment needs unescaping
        if matchdict['fragment'] is not None:
            self.fragment = urllib.unquote(matchdict['fragment']).decode(encoding)

        return self


    ### Special methods

    def __repr__(self):
        return "<{cls}({str!r})>".format(
            cls=self.__class__.__name__,
            str=str(self),
        )

    def __str__(self):
        return self.serialize()

    def __eq__(self, other):
        if isinstance(other, URI):
            return self.serialize() == other.serialize()

        return NotImplemented

    ### Internal utilities

    def _maybe_escape(self, string, also=None):
        # TODO do we need to detect % that isn't part of an escape?  (yes)
        uric = uri_grammar.charclasses['reserved'] + uri_grammar.charclasses['unreserved']
        if also:
            uric = ''.join(set(uric) - set(also))

        bad_char_rx = '([^' + re.escape(uric) + '])'
        return re.sub(bad_char_rx, lambda m: "%{0:02X}".format(ord(m.group())), string)

    ### Entire URI
    # TODO these should probably all be lazy
    # TODO and cached, with children busting caches of their parents, or maybe parents inspecting cache state of children
    # TODO the getters should probably reconstruct from parts

    def serialize(self):
        """Returns the entire URI as a bytestring."""
        return _assemble(
            ('', self._scheme, ':'),
            ('', self.opaque, ''),
            # TODO yikes
            ('#', self._fragment and self._maybe_escape(self._fragment.encode('utf8'), also='#[]'), ''),
            #('#', self._fragment, ''),
        )

    ### Scheme

    @property
    def scheme(self):
        return self._scheme

    @scheme.setter
    def scheme(self, string):
        _require_type(string, unicode)
        if not uri_grammar.match('scheme', string):
            raise InvalidURIError("Invalid scheme: {0!r}".format(string))

        # Normalize: make it lowercase
        self._scheme = string.lower()

    @scheme.deleter
    def scheme(self):
        self._scheme = None

    # Opaque -- this is the scheme-specific bit
    @property
    def opaque(self):
        return _assemble(
            ('//', self.authority, ''),
            ('', self.path_escaped, ''),
            ('?', self._query, ''),
        )

    @opaque.deleter
    def opaque(self):
        del self.authority
        self._path = []
        self._query = None

    # TODO it seems almost reasonable to want to assign a unicode to this
    # directly, for schemes that outright do not support or care about
    # authority and path.  see what the rfc says about this; i think it still
    # requires that the opaque part match the grammar, in which case assignment
    # may not work, because is that question mark part of the path or part of
    # the query?
    # ...this COULD be safe if we assumed no authority (unless there's a // of
    # course), no query, and a single path component.  but then parts would get
    # escaped when that may not be the intention.  hm hm hm.
    # perhaps assignment should mean "do whatever it takes to make this come
    # out right"?
    def parse_opaque(self, value):
        _require_type(value, str)

        # According to the latest RFC, the "opaque" bit is really something
        # like:
        #     relative-part [? query]
        # where relative-part is EITHER:
        # - an authority and an optional absolute path
        # - an absolute path
        # - a relative path
        # - or nothing.
        # That's not too hard to parse, right?

        # Find the query first.  First question mark has to be the query
        # delimiter; it's not allowed anywhere before that.
        relpart, qmark, query = value.partition('?')

        if query:
            self._query = query
        else:
            # TODO is "?" canonically a distinct query?
            self._query = None

        # Now look for an authority
        if relpart.startswith('//'):
            relpart = relpart[2:]

            # Next slash marks the path
            authority, _, path = relpart.partition('/')
            self.parse_path('/' + path)
            self.parse_authority(authority)
        else:
            # No authority at all
            del self.authority
            self.parse_path(relpart)

    ### Authority: userinfo, host, and port

    @property
    def authority(self):
        # _assemble will return an empty string given all Nones
        if self._userinfo is None and self._host is None and self._port is None:
            return None

        # Maybe add brackets around a v6 address
        host = self.host
        if host and self._host_is_v6:
            host = u'[' + host + u']'

        return _assemble(
            #('', self._userinfo, '@'),
            # TODO yikes
            ('', self._userinfo and self._maybe_escape(self._userinfo.encode('utf8'), also='/?#[]@'), '@'),
            ('', host, ''),
            # TODO yikes
            (':', self._port and str(self._port), ''),
        )

    @authority.deleter
    def authority(self):
        self._userinfo = None
        self._host = None
        self._host_is_v6 = False
        self._port = None

    def parse_authority(self, value):
        _require_type(value, str)

        # TODO do this in several places...
        # TODO this makes '' allowed even though it's technically relative...
        if self._path and self._path[0] != '':
            raise InvalidURIError(
                "Can't have an authority with a relative path: {0!r}".format(self.path))

        # The only @ allowed anywhere in an authority is after the userinfo
        if '@' in value:
            self._userinfo, hostport = value.split('@', 1)
        else:
            self._userinfo = None
            hostport = value

        # Likewise, a : may only exist before the port, EXCEPT with IPv6+
        # which are contained in square brackets for exactly this reason
        maybe_host, maybe_colon, maybe_port = hostport.rpartition(':')
        if not maybe_colon or ']' in maybe_port:
            # Either colon wasn't found, partition sucks, there's no port;
            # OR there's a bracket after the final colon, so this is a
            # bracketed IP address and there's still no port
            host = hostport
            port = None
        else:
            # It's a port!
            host = maybe_host
            port = maybe_port

        # Host is allowed to contain percent-encoding (well, if it's a
        # domain, but it's not valid otherwise anyway).
        # We can also remove square brackets with wild abandon here: they're
        # only used as delimiters for IPv6 addresses, which we don't want, and
        # they aren't legal anywhere else.
        self.host = urllib.unquote(host).decode(self._encoding).strip('[]')

        # Port must be either None, empty, or a number
        if port == '' or port is None:
            del self.port
        else:
            try:
                self.port = int(port)
            except ValueError:
                raise InvalidURIError("Bogus port: {0!r}".format(port))

    # TODO should this be split into username and password?  how would that
    # affect the setter?
    # TODO what does the RFC say about even allowing passwords?  i seem to
    # recall they are heavily discouraged; perhaps we shouldn't allow having
    # them at all, or should mask them out or delete them when serializing
    @property
    def userinfo(self):
        return self._userinfo

    @userinfo.setter
    def userinfo(self, value):
        # XXX validate and stuff
        self._userinfo = value

    @userinfo.deleter
    def userinfo(self):
        self._userinfo = None

    # TODO should this return some kind of network address object?  is that a
    # pain in the ass if you just want a string?  seems nice to be able to take
    # the domain and connect to it easily, or pop off some subdomains, or
    # whatever
    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        # TODO validate

        self._host = value
        self._check_host_is_v6()

    def _check_host_is_v6(self):
        """Flag whether the host is IPv6.  If it is, we need to add square
        brackets around it when rendering the URL.
        """
        self._host_is_v6 = (
            uri_grammar.match('IPv6address', self._host) or
            uri_grammar.match('IPvFuture', self._host)
        )


    @property
    def port(self):
        if self._port is None:
            try:
                return _default_ports[self._scheme]
            except KeyError:
                return None
        else:
            # Must be an integer, or how the heck did it get here
            return self._port

    @port.setter
    def port(self, value):
        if not isinstance(value, int) or value < 0:
            raise TypeError(
                "Expected positive int, got {0!r}".format(value))
        else:
            self._port = value

    @port.deleter
    def port(self):
        self._port = None


    @property
    def host_port(self):
        host = self._host
        if host and self._host_is_v6:
            host = u'[' + host + u']'

        return _assemble(
            ('', host, ''),
            #(':', self._port, ''),
            # TODO yikes
            (':', self._port and str(self._port), ''),
        )

    @host_port.setter
    def host_port(self, value):
        # TODO escaping?  stuff?  unclear how this should work
        self._host, self._port = value.rsplit(':', 1)
        self._host = self._host.strip('[]')
        self._check_host_is_v6()

    ### Path

    @property
    def path(self):
        """Returns the path, as a tuple of path components.

        This is necessary because it's entirely plausible to have a URI with a
        path of "/foo%2fbar", which is a single path component that happens to
        contain a slash.
        """
        # TODO i think this should be a mutable object
        # TODO an absolute path is only marked by having an empty string in
        # front; that seems silly
        # TODO maybe give this a better name like _path_parts
        return tuple(self._path)

    @path.setter
    def path(self, value):
        if isinstance(value, basestring):
            raise TypeError("Expected iterable, got {0!r}".format(value))

        # TODO i think this raises a TypeError that is lame
        path_parts = list(value)

        # Can't have an authority (//foo) and a path unless something separates them
        # TODO don't check self.authority
        if path_parts and self.authority and path_parts[0] != u'':
            raise InvalidURIError(
                "Can't have a relative path with an authority: {0!r}".format(value))

        self._path = path_parts

    @path.deleter
    def path(self):
        self._path = []

    def parse_path(self, value):
        _require_type(value, str)

        # TODO there's no real grammar rule that applies to path but i would
        # kinda like to enforce one.  but what?  allow unicode assignment?
        # bytestrings containing encoded utf8?  what if there's a question mark
        # in the parse string?

        parts = [
            urllib.unquote(part).decode(self._encoding)
            for part in value.split('/')
        ]

        self._path = parts

    # TODO add a path_string property i think.  assigning to it sorta kinda
    # makes sense most of the time.  or at least would be unambiguous.

    @property
    def path_string(self):
        """The path, as a string.

        While mighty convenient, this property has a serious pitfall: it can't
        preserve the identity of escaped slashes in path components, so it
        isn't quite idempotent.  Observe:

            uri = URI.parse('/more%2fless')
            uri.path
            # ('', 'more/less')
            uri.path_string
            # '/more/less'
            uri.path_string = uri.path_string
            uri.path
            # ('', 'more', 'less')

        In the interests of correctness, please avoid this property.
        """
        return u'/'.join(self._path)

    @path_string.setter
    def path_string(self, value):
        _require_type(value, unicode)

        # TODO should canonicalize this (and other path parse/assign
        # mechanisms): for example i believe '///' is always considered
        # equivalent to '/'.  maybe.  find out.
        self._path = value.split(u'/')

    @path_string.deleter
    def path_string(self):
        # Same as deleting the path, but hey, why not.
        self._path = []

    @property
    def path_escaped(self):
        """Returns the path, appropriate for direct inclusion in a URI.

        `path_escaped` and `parse_path` are idempotent.
        """
        return '/'.join(
            self._maybe_escape(part.encode(self._encoding), also='[]/?#')
            for part in self._path
        )

    ### Query

    @property
    def query(self):
        return self._query

    @query.setter
    def query(self, string):
        if string is None:
            self._query = None
            return

        string = self._maybe_escape(string, also='#')

        self._query = string

    ### Fragment; boring

    @property
    def fragment(self):
        return self._fragment

    @fragment.setter
    def fragment(self, value):
        _require_type(value, unicode)

        # No validation required; there's no such thing as an invalid fragment
        self._fragment = value

    @fragment.deleter
    def fragment(self):
        self._fragment = None
