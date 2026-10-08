#!/usr/bin/env python3
"""Writes ../good.jsonl and ../good.head.

A second implementation of the workflow log and its chain, written from
docs/evidence-format.md. It shares no code with the Go package, so the fixture it
writes is a check on the Go code and not a copy of it. Standard library only.

    python3 fixture.py OUTDIR

To regenerate the committed fixture, from verify/workflow:

    python3 testdata/gen/fixture.py testdata

A Go test runs this script when python3 is on the path and requires its output to
be byte-identical to the committed files.
"""
import hashlib
import json
import os
import sys

BS = chr(92)

# The events as the service writes them: JSON with no spaces, the members of
# "data" in order of name, and < > & U+2028 U+2029 written as escapes. The
# bodies are given as the text they are digested over.
LOCK = 'a' * 64
CHAIN2 = 'c' * 64
BODIES = [
    '{"type":"example.created","actor":"system","data":{"name":"Acme ' + BS + 'u003c' + BS + 'u0026' + BS + 'u003e Co"}}',
    ('{"type":"campaign.locked","actor":"admin:1","data":{"campaign":"c-1","digest":"' + LOCK + '","items":3,'
     '"sources":[{"chain_value":"' + CHAIN2 + '","collected_at":"2026-10-06T09:00:00Z","connection":"conn-1",'
     '"digest":"' + 'b' * 64 + '","seq":2}],"without_address":2}}'),
    ('{"type":"collection.completed","actor":"system","data":{"chain_value":"' + CHAIN2 + '","connection":"conn-1",'
     '"digest":"' + 'b' * 64 + '","run":"run-1","seq":2,"whole":true}}'),
    ('{"type":"example.decided","actor":"reviewer:r@example.com","data":{"big":9007199254740993,'
     '"nested":{"list":[1,"two",{"three":3}]},"note":"a ' + BS + 'u003c b ' + BS + 'u2028 é","verb":"approve"}}'),
    '{"type":"pack.built","actor":"admin:1"}',
]
RECORDED = ['2026-10-06T12:00:00.123456Z', '2026-10-06T12:00:01.123456Z', '2026-10-06T12:00:02.5Z',
            '2026-10-06T12:00:03Z', '2026-10-06T12:00:04.000000001Z']


def chain_value(seq, at, digest, prev):
    return hashlib.sha256(('%d\n%s\n%s\n%s' % (seq, at, digest, prev)).encode()).hexdigest()


def write(out):
    os.makedirs(out, exist_ok=True)
    lines, previous = [], ''
    for seq, (body, at) in enumerate(zip(BODIES, RECORDED), start=1):
        digest = hashlib.sha256(body.encode('utf-8')).hexdigest()
        chain = chain_value(seq, at, digest, previous)
        lines.append('{"sequence":%d,"recorded_at":%s,"digest":%s,"previous":%s,"chain":%s,"body":%s}' % (
            seq, json.dumps(at), json.dumps(digest), json.dumps(previous), json.dumps(chain), body))
        previous = chain
    with open(os.path.join(out, 'good.jsonl'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    with open(os.path.join(out, 'good.head'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('{"format":1,"sequence":%d,"chain":%s}' % (len(BODIES), json.dumps(previous)))
    for seq, line in enumerate(lines, start=1):
        d = json.loads(line)
        print(seq, d['digest'], d['chain'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    write(sys.argv[1])
