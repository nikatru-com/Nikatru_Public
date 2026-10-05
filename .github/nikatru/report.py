#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# shell-report.py — the public shell's verdicts, signed, to the bridge Worker.
#
# GitHub migration P4 (Private/research/session-2026-10-04/github-migration/
# PLAN.md, design items 2 and 4; lead ruling on PR #1234, finding 2). It runs in
# the TWO generated jobs at the end of each root workflow, `nikatru-collect` and
# `nikatru-report` (below), which need the gate and every lane the gate needs,
# check out ONLY the public shell repository, and run nothing from the private
# checkout. tooling/ci/gen-public-shell.mjs ships a byte copy of this file as
# shell/.github/nikatru/report.py, beside the generated <workflow>.json config of
# each root workflow (assert-public-shell.mjs limb A holds both to the generator).
# The report secret exists in the report job's last two steps (the send and its
# no-detail fallback) and nowhere else in the shell (limb H): a step that runs
# pull-request code never holds it, and the job that holds it restores nothing
# another job saved (limb I). NIKATRU_DETAIL_KEY is in the collect job's last step
# and the report job's send step only (limb J).
#
# Why Python: the job must run without the private tree, so the reporter is a
# file of the shell repository, and it needs nothing but the standard library
# (HMAC, JSON, HTTP). CodeQL in this repository analyses JavaScript/TypeScript
# only, so this file is NOT CodeQL-analysed; its one data flow — a red step's
# detail, read from a file, sealed, handed on, posted to the bridge — is the
# by-design flow, and
# tooling/ci/test/shell-report.test.mjs grades it.
#
#   Two generated jobs per root workflow, so the job that holds the report secret
#   never restores what a job that ran pull-request code saved (review of #1234,
#   finding B: an actions/cache archive is shaped by whoever saved it, not by the
#   restore's `path:`, and can overwrite this very file):
#
#   nikatru-collect — NO report secret. Restores the hand-offs and seals the detail:
#   report.py plan <cfg>    list this run+attempt's detail hand-offs (actions/cache
#                           keys) and write key_0..key_<n-1> and `overflow` to
#                           $GITHUB_OUTPUT; the job restores each into .nikatru-detail/
#   report.py place <key>   move the restored .nikatru-detail/detail.md to
#                           .nikatru-collected/<key>.md
#   report.py collect <cfg> the detail of every lane and the gate as ONE bundle,
#                           size-bounded, sealed with NIKATRU_DETAIL_KEY, written as
#                           the job output `detail`
#
#   nikatru-report — the report secret; restores nothing, runs nothing another job
#   wrote (assert-public-shell.mjs limb I). A fresh sparse checkout of this shell, then
#   /usr/bin/python3 -I .github/nikatru/report.py send <cfg>
#                           one commit status per lane the gate needs (state from
#                           NIKATRU_RESULTS, so a green re-run clears a red one), then
#                           the gate's. The bundle arrives as NIKATRU_DETAIL, plain
#                           data in `env:`; it is unsealed, parsed and checked against
#                           the config (known contexts, string values, size caps), and
#                           any bundle that fails — any error at all, deep nesting too —
#                           is dropped: the statuses still go out. Having attempted every
#                           status it writes `reported=true` to $GITHUB_OUTPUT (a file).
#   The report job's LAST step runs the same `send` WITHOUT the detail, if that output is
#   not `true`: the step above never started (a job output may be 1 MB, and Linux refuses
#   to start a process with one environment string over 128 KiB), or it died. So no
#   hand-off can withhold the statuses (review of #1245, finding 1).
#
# Why sealed: an artifact of a public repository is downloadable by anyone signed in
# (limb C), and a job output reaches a step only through an expression, whose value the
# runner prints in the step's public log header. So the bundle is encrypted and
# authenticated (HMAC-SHA256 in counter mode as the keystream, encrypt-then-MAC, the
# run+attempt bound in) under NIKATRU_DETAIL_KEY, which both jobs hold. A job that
# poisons nikatru-collect's workspace already ran pull-request code with the deploy
# key, so that key protects the detail from outsiders only; the worst a poisoned
# hand-off can do to the report job is change or drop the detail text, which a red
# step can already do. Without the key, the reports go out without detail.
#
# The bridge's contract (services/gh-bridge/src/report.ts parseReport):
#   POST <bridgeUrl>   x-bridge-signature: sha256=<HMAC-SHA256 of the raw body>
#   {run_id, run_attempt, sha, context, state, summary, detail?}
# `sha` is the private HEAD the bridge dispatched (NIKATRU_HEAD_SHA = the payload's
# sha), never the merge commit a pull-request job checks out.
#
# ⏱ 2026-10-05 (gh-bridge f1, round 3; lead ruling): THE GATE COMES ONLY FROM A RUN THAT HAS
# ONE. The gate's context is sent only when the run was dispatched for a pull request
# (NIKATRU_P_EVENT pull_request with a PR number) or for a push to main or of a tag; any
# other run reports its lanes and NOT the gate, and exits 1. The bridge dispatches nothing
# else, so this is defence in depth: a run without the PR range can never write the
# verdict the landers gate on. The bridge itself holds the context to this workflow's own
# set (services/gh-bridge/src/generated/shell.ts, written by gen-public-shell.mjs).
#
# Exit 0 every report accepted (collect: the bundle sealed) · 1 a report refused or
# not delivered (a verdict that did not land must not look green) · 2 COVERAGE LOST:
# no config, no bridge URL, no secret, no sha — nothing could be signed or sent
# (collect: no detail key, so no detail can travel).
# ─────────────────────────────────────────────────────────────────────────────
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARY_MAX_CHARS = 140
DETAIL_MAX_BYTES = 60 * 1024
CONTEXT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._/():-]{0,99}$')
SHA = re.compile(r'^[0-9a-f]{40}$')
STATE_OF = {'success': 'success', 'failure': 'failure', 'cancelled': 'error'}
# The plain bundle's cap: sealed and base64'd it stays under SEALED_MAX_CHARS, so it fits
# one environment variable (Linux caps one at 128 KiB) and a job output (1 MB).
BUNDLE_MAX_BYTES = 88 * 1024
SEALED_MAX_CHARS = 120 * 1024
SEAL_VERSION = b'\x01'
NONCE_BYTES = 16
TAG_BYTES = 32
DETAIL_DIR = '.nikatru-detail'
COLLECTED_DIR = '.nikatru-collected'


class Lost(Exception):
    """Nothing could be signed or sent: exit 2."""


def load_config(path):
    # The config is named by path in the workflow (so the tree's dead-file guard sees its
    # consumer), and only one of the generated configs beside this script is accepted.
    if not re.match(r'^\.github/nikatru/[A-Za-z0-9_-]+\.json$', path):
        raise Lost(f'{path!r} is not a config of .github/nikatru/')
    try:
        with open(path, encoding='utf-8') as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise Lost(f'{path} is unreadable: {e}')
    for k in ('prefix', 'slots', 'gate', 'lanes'):
        if k not in cfg:
            raise Lost(f'{path} has no `{k}`')
    for c in [cfg['gate']] + list(cfg['lanes']):
        if not CONTEXT.match(c.get('context', '')):
            raise Lost(f'{path}: {c.get("context")!r} is not a status context the bridge accepts')
    return cfg


def run_of(env):
    return f"{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"


def run_prefix(cfg, env):
    return f"{cfg['prefix']}{run_of(env)}-"


def member_of(key, prefix):
    """`<stem>.<job>` of a hand-off key, or None when the key is not this run's."""
    if not key.startswith(prefix):
        return None
    rest = key[len(prefix):]
    head, _, index = rest.rpartition('.')
    return head if head and index.isdigit() else None


def tail_bytes(text, cap):
    raw = text.encode('utf-8')
    if len(raw) <= cap:
        return text
    note = '(earlier detail cut to fit the report)\n'
    cut = raw[len(raw) - (cap - len(note.encode('utf-8'))):].decode('utf-8', errors='ignore')
    nl = cut.find('\n')
    if 0 <= nl < len(cut) - 1:
        cut = cut[nl + 1:]
    return note + cut


def join_detail(sections, cap=DETAIL_MAX_BYTES):
    """Sections joined; over the cap, each keeps an equal share of its own tail."""
    sections = [s for s in sections if s.strip()]
    if not sections:
        return ''
    whole = '\n'.join(sections)
    if len(whole.encode('utf-8')) <= cap:
        return whole
    share = cap // len(sections) - 1
    return '\n'.join(tail_bytes(s, share) for s in sections)


def signature(secret, raw):
    return 'sha256=' + hmac.new(secret.encode('utf-8'), raw, hashlib.sha256).hexdigest()


# ── the sealed bundle ────────────────────────────────────────────────────────

class Refused(ValueError):
    """A detail bundle that is not this run's well-formed, sealed plain data."""


def _seal_keys(key):
    k = key.encode('utf-8')
    return (hmac.new(k, b'nikatru-detail/enc', hashlib.sha256).digest(),
            hmac.new(k, b'nikatru-detail/mac', hashlib.sha256).digest())


def _keystream_xor(enc, nonce, data):
    blocks = (len(data) + 31) // 32
    stream = b''.join(hmac.new(enc, nonce + i.to_bytes(8, 'big'), hashlib.sha256).digest() for i in range(blocks))
    if not data:
        return b''
    return (int.from_bytes(data, 'big') ^ int.from_bytes(stream[:len(data)], 'big')).to_bytes(len(data), 'big')


def _tag(mac, run, nonce, ct):
    return hmac.new(mac, run.encode('utf-8') + b'\0' + SEAL_VERSION + nonce + ct, hashlib.sha256).digest()


def seal(key, run, plain, nonce=None):
    """base64(version · nonce · ciphertext · tag), bound to `run` (`<run_id>-<attempt>`)."""
    enc, mac = _seal_keys(key)
    nonce = nonce or os.urandom(NONCE_BYTES)
    ct = _keystream_xor(enc, nonce, plain)
    return base64.b64encode(SEAL_VERSION + nonce + ct + _tag(mac, run, nonce, ct)).decode('ascii')


def unseal(key, run, sealed):
    if len(sealed) > SEALED_MAX_CHARS:
        raise Refused(f'{len(sealed)} characters, over the {SEALED_MAX_CHARS} cap')
    try:
        raw = base64.b64decode(sealed, validate=True)
    except ValueError:
        raise Refused('not base64')
    if len(raw) < 1 + NONCE_BYTES + TAG_BYTES or raw[:1] != SEAL_VERSION:
        raise Refused('not a sealed bundle of this version')
    enc, mac = _seal_keys(key)
    nonce, ct, tag = raw[1:1 + NONCE_BYTES], raw[1 + NONCE_BYTES:-TAG_BYTES], raw[-TAG_BYTES:]
    if not hmac.compare_digest(tag, _tag(mac, run, nonce, ct)):
        raise Refused("its tag does not verify (another key, another run, or altered)")
    return _keystream_xor(enc, nonce, ct)


def fit_bundle(details, cap=BUNDLE_MAX_BYTES):
    """{context: detail} as compact JSON bytes within `cap`: over it, every detail keeps an
    equal, shrinking share of its own tail; past the smallest share, no detail at all."""
    share = DETAIL_MAX_BYTES
    while True:
        raw = json.dumps({c: tail_bytes(t, share) for c, t in details.items()}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if len(raw) <= cap:
            return raw
        if share <= 1024:
            return b'{}'
        share = share * 3 // 4


def parse_bundle(plain, cfg):
    """The plain bundle as {context: detail}, or Refused: JSON, an object, only the
    config's contexts, string values within the caps. Data only: nothing in it is run."""
    if len(plain) > BUNDLE_MAX_BYTES:
        raise Refused(f'{len(plain)} bytes, over the {BUNDLE_MAX_BYTES} cap')
    try:
        bundle = json.loads(plain.decode('utf-8'))
    except Exception as e:  # RecursionError (deep nesting) is a RuntimeError, not a ValueError
        raise Refused(f'not UTF-8 JSON this reporter can read ({type(e).__name__})')
    if not isinstance(bundle, dict):
        raise Refused('not a JSON object')
    known = {c['context'] for c in [cfg['gate']] + list(cfg['lanes'])}
    for c, text in bundle.items():
        if c not in known:
            raise Refused(f'{c[:100]!r} is not a status context of this config')
        if not isinstance(text, str) or len(text.encode('utf-8')) > DETAIL_MAX_BYTES:
            raise Refused(f'the detail of {c!r} is not a string within {DETAIL_MAX_BYTES} bytes')
    return bundle


# ── plan ─────────────────────────────────────────────────────────────────────

def list_keys(env, prefix):
    api = env.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')
    repo = env['GITHUB_REPOSITORY']
    keys = []
    for page in range(1, 6):
        q = urllib.parse.urlencode({'key': prefix, 'per_page': 100, 'page': page})
        req = urllib.request.Request(f'{api}/repos/{repo}/actions/caches?{q}', headers={
            'authorization': f"Bearer {env.get('GH_TOKEN', '')}",
            'accept': 'application/vnd.github+json',
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.load(r)
        got = [c['key'] for c in body.get('actions_caches', []) if c.get('key', '').startswith(prefix)]
        keys.extend(got)
        if len(body.get('actions_caches', [])) < 100:
            break
    return sorted(set(keys))


def plan(env, cfg):
    prefix = run_prefix(cfg, env)
    slots = int(cfg['slots'])
    try:
        keys = [k for k in list_keys(env, prefix) if member_of(k, prefix)]
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        # The statuses still go out (send runs `if: always()`); only the detail is lost, and said.
        with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write('\n'.join(f'key_{i}=' for i in range(slots)) + '\noverflow=\n')
        print(f'x plan: the hand-offs could not be listed ({str(e)[:160]}); the reports go out without detail')
        return 1
    lines = [f'key_{i}={keys[i] if i < len(keys) else ""}' for i in range(slots)]
    lines.append('overflow=' + ','.join(keys[slots:]))
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'ok plan: {len(keys)} red job detail(s) handed over'
          + (f'; {len(keys) - slots} beyond the {slots} restore slot(s)' if len(keys) > slots else ''))
    return 0


# ── place ────────────────────────────────────────────────────────────────────

def place(key):
    src = os.path.join(DETAIL_DIR, 'detail.md')
    if not re.match(r'^[A-Za-z0-9._-]+$', key) or not os.path.isfile(src):
        print(f'x place: no restored detail for {key!r}')
        return 1
    os.makedirs(COLLECTED_DIR, exist_ok=True)
    shutil.move(src, os.path.join(COLLECTED_DIR, f'{key}.md'))
    shutil.rmtree(DETAIL_DIR, ignore_errors=True)
    print(f'ok place: {key}')
    return 0


# ── collect ──────────────────────────────────────────────────────────────────

def collected(prefix):
    """{member: [detail text, ...]} from .nikatru-collected/, in key order."""
    out = {}
    if not os.path.isdir(COLLECTED_DIR):
        return out
    for name in sorted(os.listdir(COLLECTED_DIR)):
        member = member_of(name[:-3], prefix) if name.endswith('.md') else None
        if member is None:
            continue
        with open(os.path.join(COLLECTED_DIR, name), encoding='utf-8', errors='replace') as f:
            out.setdefault(member, []).append(f.read())
    return out


def detail_for(members, details):
    # A member is `<workflow>.<job>`; a lane's prefixes end in `.` (`ci.guard-tests.` or a
    # whole called workflow, `lane-workers.`), so `ci.guard-tests` never takes `ci.guard-tests-floor`.
    return join_detail([t for m, texts in details.items() if any(f'{m}.'.startswith(p) for p in members) for t in texts])


def build(context, state, env, detail):
    run_id, attempt = int(env['GITHUB_RUN_ID']), int(env['GITHUB_RUN_ATTEMPT'])
    body = {
        'run_id': run_id,
        'run_attempt': attempt,
        'sha': env['NIKATRU_HEAD_SHA'],
        'context': context,
        'state': state,
        'summary': f'{context}: {state} (public run {run_id}, attempt {attempt})'[:SUMMARY_MAX_CHARS],
    }
    if state in ('failure', 'error') and detail.strip():
        body['detail'] = tail_bytes(detail, DETAIL_MAX_BYTES)
    return body


def post(url, secret, body, opener=urllib.request.urlopen):
    raw = json.dumps(body, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=raw, method='POST', headers={
        'content-type': 'application/json',
        'x-bridge-signature': signature(secret, raw),
    })
    try:
        with opener(req, timeout=30) as r:
            return r.status, ''
    except urllib.error.HTTPError as e:
        try:
            why = str(json.loads(e.read().decode('utf-8')).get('error', ''))[:200]
        except (ValueError, AttributeError):
            why = ''
        return e.code, why
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)[:200]


def bundle_details(env, cfg):
    """{context: detail} of every lane and the gate, from this run's collected hand-offs;
    the gate's names the red jobs whose detail no restore slot carried."""
    prefix = run_prefix(cfg, env)
    details = collected(prefix)
    overflow = [k for k in env.get('NIKATRU_OVERFLOW', '').split(',') if k]
    out = {}
    for item in list(cfg['lanes']) + [cfg['gate']]:
        detail = detail_for(item['members'], details)
        if item is cfg['gate'] and overflow:
            detail += '\n\n(' + str(len(overflow)) + ' more red job(s) handed over detail this report could not restore: ' + ', '.join(member_of(k, prefix) or k for k in overflow) + ')\n'
        if detail.strip():
            out[item['context']] = detail
    return out


def collect(env, cfg):
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
        key = env.get('NIKATRU_DETAIL_KEY', '')
        if not key:
            f.write('detail=\n')
            raise Lost('NIKATRU_DETAIL_KEY is not set: no detail can travel to the report job (its statuses still go out)')
        details = bundle_details(env, cfg)
        plain = fit_bundle(details)
        f.write('detail=' + seal(key, run_of(env), plain) + '\n')
    print(f'ok collect: detail for {len(details)} status(es), {len(plain)} byte(s) sealed for the report job')
    return 0


# ── send ─────────────────────────────────────────────────────────────────────

def received_details(env, cfg):
    """The sealed bundle nikatru-collect handed over, unsealed and checked; {} when there is
    none or it is refused. It is data: parsed as JSON, never run, imported or written out."""
    sealed = env.get('NIKATRU_DETAIL', '')
    if not sealed:
        print('-- detail: none handed over; the reports go out without detail')
        return {}
    key = env.get('NIKATRU_DETAIL_KEY', '')
    if not key:
        print('x  detail: NIKATRU_DETAIL_KEY is not set; the reports go out without detail')
        return {}
    try:
        return parse_bundle(unseal(key, run_of(env), sealed), cfg)
    except Refused as e:
        print(f'x  detail refused: {e}; the reports go out without detail')
        return {}
    except Exception as e:  # whatever a hand-off does, the statuses still go out
        print(f'x  detail refused: it could not be read ({type(e).__name__}); the reports go out without detail')
        return {}


def gate_origin_ok(env):
    """True when this run may report the gate: a pull request with a number, or a push to main or of a tag."""
    event = env.get('NIKATRU_P_EVENT', '')
    ref = env.get('NIKATRU_P_REF', '')
    if event == 'pull_request':
        return re.fullmatch(r'[1-9][0-9]{0,9}', env.get('NIKATRU_P_PR', '')) is not None
    return event == 'push' and (ref == 'refs/heads/main' or ref.startswith('refs/tags/'))


def send(env, cfg, opener=urllib.request.urlopen):
    url = cfg.get('bridgeUrl')
    if not url:
        raise Lost('the config names no bridge URL (generated before services/gh-bridge/wrangler.jsonc was in the tree)')
    secret = env.get('BRIDGE_REPORT_SECRET', '')
    if not secret:
        raise Lost('BRIDGE_REPORT_SECRET is not set: no report can be signed')
    if not SHA.match(env.get('NIKATRU_HEAD_SHA', '')):
        raise Lost('NIKATRU_HEAD_SHA is not the 40-hex sha the bridge dispatched')
    try:
        results = json.loads(env.get('NIKATRU_RESULTS', ''))
    except ValueError:
        raise Lost('NIKATRU_RESULTS is not the JSON map of job results the report job is given')
    details = received_details(env, cfg)
    failed = 0
    for item in list(cfg['lanes']) + [cfg['gate']]:
        state = STATE_OF.get(results.get(item['job'], ''))
        if state is None:
            print(f"-- {item['context']}: {results.get(item['job'], 'absent')}, not reported")
            continue
        if item is cfg['gate'] and not gate_origin_ok(env):
            failed += 1
            print(f"x  {item['context']}: NOT reported — this run is not a pull request, main or a tag run "
                  f"(event {env.get('NIKATRU_P_EVENT', '')!r}, ref {env.get('NIKATRU_P_REF', '')!r}); only such a run may write the gate")
            continue
        status, why = post(url, secret, build(item['context'], state, env, details.get(item['context'], '')), opener)
        ok = 200 <= status < 300
        failed += 0 if ok else 1
        print(f"{'ok' if ok else 'x '} {item['context']} {state} -> HTTP {status}{f' ({why})' if why and not ok else ''}")
    # Every status was attempted: the report job's fallback step (no detail) need not run.
    if env.get('GITHUB_OUTPUT'):
        with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write('reported=true\n')
    return 1 if failed else 0


def main(argv, env):
    try:
        if len(argv) == 2 and argv[0] == 'place':
            return place(argv[1])
        if len(argv) == 2 and argv[0] in ('plan', 'collect', 'send'):
            cfg = load_config(argv[1])
            return {'plan': plan, 'collect': collect, 'send': send}[argv[0]](env, cfg)
        print('usage: report.py plan <config> | place <key> | collect <config> | send <config>', file=sys.stderr)
        return 2
    except Lost as e:
        print(f'x COVERAGE LOST - report.py: {e}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], os.environ))
