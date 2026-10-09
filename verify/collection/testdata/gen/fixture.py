#!/usr/bin/env python3
"""Writes ../good.jsonl and ../good.head, and prints test vectors.

This is a second implementation of the collection digest and the chain of
docs/evidence-format.md, written from that document. It shares no code with the
Go package, so the fixture it writes is a check on the Go code and not a copy
of it. Standard library only.

    python3 fixture.py OUTDIR      write good.jsonl and good.head into OUTDIR
    python3 fixture.py --vectors   print the digests of the tie examples and of a run full of escapes

To regenerate the committed fixture, from verify/collection:

    python3 testdata/gen/fixture.py testdata

A Go test runs this script when python3 is on the path and requires its output to
be byte-identical to the committed files.
"""
import hashlib
import json
import os
import sys

BS = chr(92)


def esc(s):
    """A string as the spec's Strings section writes it."""
    out = json.dumps(s, ensure_ascii=False)  # quotes, backslash, \b \f \n \r \t, other controls as \u00xx
    out = out.replace('<', BS + 'u003c').replace('>', BS + 'u003e').replace('&', BS + 'u0026')
    return out.replace(chr(0x2028), BS + 'u2028').replace(chr(0x2029), BS + 'u2029')


def enc(v):
    """Compact JSON; an ordered object is a tuple of (name, value) pairs."""
    if v is None:
        return 'null'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return esc(v)
    if isinstance(v, list):
        return '[' + ','.join(enc(x) for x in v) + ']'
    if isinstance(v, tuple):
        return '{' + ','.join(esc(k) + ':' + enc(x) for k, x in v) + '}'
    raise TypeError(v)


NAMES = {1: 'identity', 2: 'grouping', 3: 'entitlement', 4: 'resource', 5: 'scope', 0: 'unspecified'}


def key_text(k):
    scope, typ, ident = k
    return scope + '/' + NAMES.get(typ, 'unrecognised(%d)' % typ) + '/' + ident


def canonical_scope(s):
    items = [('id', s['id']), ('status', s['status']), ('reason', s.get('reason', '')),
             ('activity_available', s['activity_available'])]
    if s.get('activity_undetermined'):
        items.append(('activity_undetermined', True))
    return enc(tuple(items))


def canonical(run):
    # Scopes: by id, then by the bytes of the rendering.
    scopes = sorted(((s['id'].encode(), canonical_scope(s).encode()) for s in run['scopes']))
    grants = []
    for g in run['observed']:
        via = [key_text(k) for k in g.get('via', [])]
        text = enc((('identity', key_text(g['identity'])), ('entitlement', key_text(g['entitlement'])),
                    ('fidelity', g['fidelity']), ('via', via if via else None)))
        order = '%s\x00%s\x00%s\x00%d' % (key_text(g['identity']), key_text(g['entitlement']), '>'.join(via), g['fidelity'])
        grants.append((order.encode(), text.encode()))
    grants.sort()
    c = run['counts']
    counts = enc((('identities', c[0]), ('groupings', c[1]), ('entitlements', c[2]),
                  ('resources', c[3]), ('grants', c[4]), ('referenced', c[5])))
    return ('{"source":' + esc(run['source']) + ',"started_at":' + esc(run['started_at']) +
            ',"whole":' + enc(run['whole']) + ',"verdict":' + enc(run['verdict']) + ',"cause":' + enc(run['cause']) +
            ',"scopes":' + ('[' + ','.join(t.decode() for _, t in scopes) + ']' if scopes else 'null') +
            ',"counts":' + counts +
            ',"observed":' + ('[' + ','.join(t.decode() for _, t in grants) + ']' if grants else 'null') + '}')


def line_run(run):
    """The run as a line stores it: input order, empty reason / route / flag left out."""
    def k(x):
        return (('scope', x[0]), ('type', x[1]), ('id', x[2]))
    scopes = []
    for s in run['scopes']:
        items = [('id', s['id']), ('status', s['status'])]
        if s.get('reason'):
            items.append(('reason', s['reason']))
        items.append(('activity_available', s['activity_available']))
        if s.get('activity_undetermined'):
            items.append(('activity_undetermined', True))
        scopes.append(tuple(items))
    observed = []
    for g in run['observed']:
        items = [('identity', k(g['identity'])), ('entitlement', k(g['entitlement'])), ('fidelity', g['fidelity'])]
        if g.get('via'):
            items.append(('via', [k(v) for v in g['via']]))
        observed.append(tuple(items))
    c = run['counts']
    return (('source', run['source']), ('started_at', run['started_at']), ('whole', run['whole']),
            ('verdict', run['verdict']), ('cause', run['cause']), ('scopes', scopes if scopes else None),
            ('counts', (('identities', c[0]), ('groupings', c[1]), ('entitlements', c[2]),
                        ('resources', c[3]), ('grants', c[4]), ('referenced', c[5]))),
            ('observed', observed if observed else None))


def chain_value(seq, at, digest, prev):
    return hashlib.sha256(('%d\n%s\n%s\n%s' % (seq, at, digest, prev)).encode()).hexdigest()


def K(scope, typ, ident):
    return (scope, typ, ident)


RUNS = [
    dict(source='alpha', started_at='2026-03-01T00:00:00Z', whole=True, verdict=1, cause=0,
         scopes=[], counts=(0, 0, 0, 0, 0, 0), observed=[]),
    dict(source='alpha', started_at='2026-03-02T08:30:00.5Z', whole=False, verdict=2, cause=77,
         scopes=[dict(id='ops<&>', status=1, activity_available=True),
                 dict(id='équipe-日本', status=9, reason='token expired', activity_available=False,
                      activity_undetermined=True)],
         counts=(3, 1, 2, 1, 4, 1),
         observed=[
             dict(identity=K('ops<&>', 1, 'zoë'), entitlement=K('ops<&>', 3, 'admin'), fidelity=2,
                  via=[K('ops<&>', 2, 'platform'), K('ops<&>', 2, 'root')]),
             dict(identity=K('ops<&>', 1, 'al'), entitlement=K('ops<&>', 3, 'admin'), fidelity=1),
             dict(identity=K('ops<&>', 1, 'al0'), entitlement=K('ops<&>', 3, 'read'), fidelity=3),
             dict(identity=K('ops<&>', 1, 'zoë'), entitlement=K('ops<&>', 3, 'admin'), fidelity=2,
                  via=[K('ops<&>', 2, 'platform')]),
             dict(identity=K('ops<&>', 7, 'odd'), entitlement=K('ops<&>', 0, 'none'), fidelity=99),
         ]),
    dict(source='alpha', started_at='2026-03-03T08:30:00.123456789Z', whole=True, verdict=1, cause=0,
         scopes=[dict(id='ops<&>', status=1, activity_available=True)],
         counts=(1, 0, 1, 0, 1, 0),
         observed=[dict(identity=K('ops<&>', 1, 'al'), entitlement=K('ops<&>', 3, 'admin'), fidelity=2)]),
]
RECORDED = ['2026-03-01T00:00:10Z', '2026-03-02T08:30:10.25Z', '2026-03-03T08:30:10.123456789Z']


def write(out):
    os.makedirs(out, exist_ok=True)
    lines, previous = [], ''
    for seq, (run, at) in enumerate(zip(RUNS, RECORDED), start=1):
        digest = hashlib.sha256(canonical(run).encode()).hexdigest()
        chain = chain_value(seq, at, digest, previous)
        lines.append(enc((('sequence', seq), ('recorded_at', at), ('digest', digest), ('previous', previous),
                          ('chain', chain), ('run', line_run(run)))))
        previous = chain
    with open(os.path.join(out, 'good.jsonl'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    with open(os.path.join(out, 'good.head'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(enc((('format', 1), ('sequence', len(RUNS)), ('chain', previous))))


def vectors():
    empty = dict(source='', started_at='0001-01-01T00:00:00Z', whole=False, verdict=0, cause=0,
                 scopes=[], counts=(0, 0, 0, 0, 0, 0), observed=[])
    # Two grants whose ordering texts are equal: one route through a key whose id holds ">".
    a = dict(identity=K('s', 1, 'a'), entitlement=K('s', 3, 'x'), fidelity=1, via=[K('s', 2, 'g>s/grouping/h')])
    b = dict(identity=K('s', 1, 'a'), entitlement=K('s', 3, 'x'), fidelity=1, via=[K('s', 2, 'g'), K('s', 2, 'h')])
    # A name with every character that needs an escape: backspace, form feed, line feed,
    # carriage return, tab, U+0001, DEL, U+2028, U+2029, <, > and &, a real U+FFFD, a quote,
    # a backslash and a slash, and non-ASCII.
    name = ('a<b>&c' + chr(8) + chr(12) + chr(10) + chr(13) + chr(9) + chr(1) + chr(127) + chr(0x2028) + chr(0x2029) +
            chr(0xe9) + chr(0xfffd) + '"' + chr(92) + '/')
    escapes = dict(source=name, started_at='2026-05-06T07:08:09Z', whole=True, verdict=1, cause=0,
                   scopes=[dict(id=name, status=1, reason=name, activity_available=True)],
                   counts=(1, 0, 1, 0, 1, 0),
                   observed=[dict(identity=K('s', 1, name), entitlement=K('s', 3, 'e'), fidelity=1)])
    for name, run in (
        ('escapes', escapes),
        ('grants tie', dict(empty, observed=[a, b])),
        ('scopes tie', dict(empty, scopes=[dict(id='s', status=2, activity_available=False),
                                           dict(id='s', status=1, activity_available=True)])),
    ):
        text = canonical(run)
        print(name, hashlib.sha256(text.encode()).hexdigest())
        print('  ', text)


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--vectors':
        vectors()
    elif len(sys.argv) == 2:
        write(sys.argv[1])
    else:
        sys.exit(__doc__)
