import re
import string

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


_default_ports = dict(
    ftp=21,
    http=80,
    https=443,
    ssh=22,
)


def _assemble(*parts):
    # TODO docs
    buf = []
    for part in parts:
        before, middle, after = part
        if middle is not None:
            buf.extend(part)

    return ''.join(buf)




class URI(object):

    # TODO turn this into a helpful comment or doc or something
    '''
    # URIs may take several forms:
    # Absolute, hierarchical: scheme:

    - scheme
    - opaque (no longer exists, really; now is just a path)
        - authority
            - userinfo
                - username
                - password
            - host
                - hostname
                - ipv4
                - ipv6
            - port
        - path
            - params
        - query
            - mapping
    - fragment


    scheme://userinfo@authority:port/path?query#fragment

    scheme:opaque#fragment
    scheme://authority/abs_path?query#fragment
    scheme:/abs_path?query#fragment
    //authority/abs_path?query#fragment
    /abs_path?query#fragment
    rel_path?query#fragment

    '''

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
    _scheme = None

    def __init__(self, string="", strict=True):
        self.strict = strict
        self.original = string

    def __repr__(self):
        return "<{cls}({str!r})>".format(
            cls=self.__class__.__name__,
            str=str(self),
        )

    def __str__(self):
        return self.original

    def __eq__(self, other):
        # TODO this emulates the perl behavior but i am unsure about it still.
        if isinstance(other, URI):
            return self.canonical == other.canonical

        if isinstance(other, str):
            return self.canonical == URI(other).canonical

        return NotImplemented

    # TODO these should probably all be lazy
    # TODO and cached, with children busting caches of their parents, or maybe parents inspecting cache state of children
    # TODO the getters should probably reconstruct from parts

    @property
    def canonical(self):
        # TODO this should probably do something with escapes and unicodes and whatnot
        return _assemble(
            ('', self.scheme, ':'),
            ('', self.opaque, ''),
            ('#', self.fragment, ''),
        )

    @property
    def original(self):
        return _assemble(
            ('', self.raw_scheme, ':'),
            ('', self.opaque, ''),
            ('#', self.fragment, ''),
        )

    @original.setter
    def original(self, string):
        #if not string:
        #    raise InvalidURIError("Empty string can't be a URI")

        # scheme:opaque#fragment
        #match = self.simple_uri_rx.match(string)
        match = uri_grammar.match('URI', string) or uri_grammar.match('relative-ref', string)
        if not match:
            # This should actually be impossible; the string isn't empty, and
            # the regexes match any one or more characters
            # TODO i'm lying!  //a:b raises
            raise InvalidURIError

        self._update_parts(match)

        #{'IPv6address': None, 'IP_literal': None, 'fragment': 'frag', 'IPvFuture': None, 'reg_name': 'host', 'hier_part': '//host:80/path', 'path_rootless': None, 'host': 'host', 'path_abempty': '/path', 'authority': 'host:80', 'path_absolute': None, 'query': 'query', 'path_empty': None, 'scheme': 'foo', 'port': '80', 'userinfo': None}

        self._original = string



    def _update_parts(self, match):
        if 'scheme' in match:
            self._scheme = match['scheme']

        if 'authority' in match:
            self._authority = match['authority']
        if 'userinfo' in match:
            self._userinfo = match['userinfo']
        if 'host' in match:
            self._host = match['host']
        if 'port' in match:
            self._port = match['port']

        any_path_key = False
        for path_key in ('path_abempty', 'path_absolute', 'path_noscheme', 'path_rootless', 'path_empty'):
            if path_key not in match:
                continue

            any_path_key = True
            if match[path_key] is not None:
                self._path = match[path_key]
                break
        else:
            if any_path_key:
                self._path = None

        if 'query' in match:
            self._query = match['query']

        if 'fragment' in match:
            self._fragment = match['fragment']

        # TODO: capture the authority /parts/; capture the path type, maybe?
        # split path on ;s?  parse query!  urldecode!  omg all the things.

    def _maybe_escape(self, string, also=None):
        # TODO do we need to detect % that isn't part of an escape?  (yes)
        uric = uri_grammar.charclasses['reserved'] + uri_grammar.charclasses['unreserved']
        if also:
            uric = ''.join(set(uric) - set(also))

        bad_char_rx = '([^' + re.escape(uric) + '])'
        return re.sub(bad_char_rx, lambda m: "%{0:02X}".format(ord(m.group())), string)


    # Scheme
    @property
    def raw_scheme(self):
        return self._scheme

    @property
    def scheme(self):
        if self._scheme is not None:
            return self._scheme.lower()

        return self._scheme

    @scheme.setter
    def scheme(self, string):
        if string is not None and not uri_grammar.match('scheme', string):
            raise InvalidURIError("Invalid scheme")

        self._scheme = string


    # Opaque -- this is the scheme-specific bit
    @property
    def opaque(self):
        return _assemble(
            ('//', self._authority, ''),
            ('', self._path, ''),
            ('?', self._query, ''),
        )

    @opaque.setter
    def opaque(self, string):
        if string is None:
            string = ''

        string = self._maybe_escape(string, also='#')

        # TODO this uses relative-ref.  is that right???
        # TODO should this clear out authority stuff
        match = uri_grammar.match('relative-opaque', string)
        self._update_parts(match)


    @property
    def authority(self):
        return self._authority

    @authority.setter
    def authority(self, string):
        if string is None:
            # TODO actually needs to clear out a few other things too
            self._authority = None
            return

        # Authority is a little tricky to escape manually.  It looks like:
        #     userinfo @ host : port
        # Port must be digits, but userinfo and host can ultimately be anything
        # in unreserved or sub-delims.
        # Note that this means gen-delims are disallowed entirely (except for
        # :, allowed in userinfo only).

        # Find userinfo first
        if '@' in string:
            userinfo, string = string.split('@', 1)
        else:
            userinfo = None

        # And then the port
        port = None
        try:
            colon_pos = string.rindex(':')
        except ValueError:
            pass
        else:
            possible_port = string[colon_pos + 1:]
            if possible_port == '' or possible_port.isdigit():
                string = string[:colon_pos]
                port = possible_port

        # Escape and assign userinfo
        if userinfo:
            userinfo = self._maybe_escape(userinfo, also='[]/?#@')
        self._userinfo = userinfo

        host = self._maybe_escape(string, also='[]:/?#@')
        match = uri_grammar.match('host', host)
        self._update_parts(match)

        self._port = port

        self._recompute_authority()

    def _recompute_authority(self):
        # After changing userinfo, host, or port, reassemble the authority
        # TODO does this need to exist, or should authority be lazy like
        # everything else?  several things check _authority...
        self._authority = _assemble(
            ('', self._userinfo, '@'),
            ('', self._host, ''),
            (':', self._port, ''),
        )

        # TODO need to do this in several places...  maybe a renormalize()
        # called after every set
        if self._authority and self._path and self._path[0] != '/':
            self._path = '/' + self._path

    @property
    def host(self):
        # Strip off square brackets.  IPv6 (and future IP address schemes)
        # include them, but they're not really part of the address.  This is a
        # clunky fix, but it works, because square brackets aren't legal
        # anywhere else in a host.
        return self._host.strip('[]')

    @host.setter
    def host(self, value):
        # TODO validate

        # Possibly add brackets for ipv6
        if uri_grammar.match('IPv6address', value) or uri_grammar.match('IPvFuture', value):
            value = '[' + value + ']'

        self._host = value
        self._recompute_authority()

    @property
    def raw_host(self):
        return self._host


    @property
    def port(self):
        if self._port is None or self._port == '':
            try:
                return _default_ports[self._scheme]
            except KeyError:
                return None
        else:
            # Must be an integer, or how the heck did it get here
            return int(self._port)

    @port.setter
    def port(self, value):
        if value is None:
            self._port = None
        elif not isinstance(value, int) or value < 0:
            raise TypeError(
                "Expected None or positive int; got {0!r}".format(value))
        else:
            self._port = str(value)

        self._recompute_authority()

    @property
    def raw_port(self):
        return self._port

    @raw_port.setter
    def raw_port(self, value):
        # TODO validate
        self._port = value
        self._recompute_authority()


    @property
    def host_port(self):
        return _assemble(
            ('', self._host, ''),
            (':', self._port, ''),
        )

    @host_port.setter
    def host_port(self, value):
        # TODO escaping?  stuff?  unclear how this should work
        self._host, self._port = value.rsplit(':', 1)
        self._recompute_authority()


    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, string):
        if string is None:
            # Paths can't really be "missing" in the sense that other parts
            # can, because they have no delimiter.  So a missing path is really
            # an empty path
            self._path = ''
            return

        string = self._maybe_escape(string, also='#?')

        # Can't have an authority (//foo) and a path unless something separates them
        if string and self._authority and not string.startswith('/'):
            string = '/' + string

        # TODO there's no real grammar rule that applies to path
        self._path = string


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


    # Fragment; boring
    @property
    def fragment(self):
        return self._fragment

    @fragment.setter
    def fragment(self, string):
        if string is None:
            self._fragment = None
            return

        match = uri_grammar.match('fragment', string)
        # XXX ?????? escape?
        if not match:
            raise InvalidURIError("Invalid fragment")

        self._update_parts(match)
