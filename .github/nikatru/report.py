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
# another job saved (limb I). NIKATRU_DETAIL_KEY is in each quiet job's hand-off
# step and the report job's send step only (limb J).
#
# Why Python: the job must run without the private tree, so the reporter is a
# file of the shell repository, and it needs nothing but the standard library
# (HMAC, JSON, HTTP). CodeQL in this repository analyses JavaScript/TypeScript
# only, so this file is NOT CodeQL-analysed; its one data flow — a red step's
# detail, read from a file, sealed, handed on, posted to the bridge — is the
# by-design flow, and
# tooling/ci/test/shell-report.test.mjs grades it.
#
#   Every quiet job hands its red detail over SEALED (lead ruling p7-bridge-payload-r3,
#   item 3: the private repo's test output and PR text never sit in plain text in the
#   PUBLIC repo's Actions cache). Its generated hand-off step runs, from the private
#   checkout, this same file:
#   shell-report.py handoff the tail of $RUNNER_TEMP/report-detail.md, sealed with
#                           NIKATRU_DETAIL_KEY and bound to its own cache key
#                           (NIKATRU_HANDOFF), written as .nikatru-detail/detail.sealed,
#                           and `has=true` to $GITHUB_OUTPUT so actions/cache/save runs;
#                           no key, no hand-off: nothing is ever cached in the clear
#
#   Two generated jobs per root workflow, so the job that holds the report secret
#   never restores what a job that ran pull-request code saved (review of #1234,
#   finding B: an actions/cache archive is shaped by whoever saved it, not by the
#   restore's `path:`, and can overwrite this very file):
#
#   nikatru-collect — NO report secret, NO detail key. Restores the sealed hand-offs:
#   report.py plan <cfg>    list this run+attempt's detail hand-offs (actions/cache
#                           keys) and write key_0..key_<n-1> and `overflow` to
#                           $GITHUB_OUTPUT; the job restores each into .nikatru-detail/
#   report.py place <key>   move the restored .nikatru-detail/detail.sealed to
#                           .nikatru-collected/<key>.sealed
#   report.py collect <cfg> every restored hand-off, carried through UNCHANGED (still
#                           sealed), as ONE JSON bundle {v, handoffs: {key: sealed},
#                           unrestored: [key]} within SEALED_MAX_CHARS, written as the
#                           job output `detail`; one that does not fit is named only
#
#   nikatru-report — the report secret; restores nothing, runs nothing another job
#   wrote (assert-public-shell.mjs limb I). A fresh sparse checkout of this shell, then
#   /usr/bin/python3 -I .github/nikatru/report.py send <cfg>
#                           one commit status per lane the gate needs (state from
#                           NIKATRU_RESULTS, so a green re-run clears a red one), then
#                           the gate's. The bundle arrives as NIKATRU_DETAIL, plain
#                           data in `env:`; it is unsealed, parsed and checked against
#                           its own key (known members of this run+attempt, size caps).
#                           A bundle that fails — another key, another run, a hand-off
#                           moved to another key, altered, malformed — is COVERAGE LOST:
#                           every status still goes out without detail, and the step
#                           exits 2, never an empty pass. Having attempted every
#                           status it writes `reported=true` to $GITHUB_OUTPUT (a file).
#   The report job's LAST step runs the same `send` WITHOUT the detail, if that output is
#   not `true`: the step above never started (a job output may be 1 MB, and Linux refuses
#   to start a process with one environment string over 128 KiB), or it died. So no
#   hand-off can withhold the statuses (review of #1245, finding 1).
#
# Why sealed AT HAND-OFF: an actions/cache entry of a public repository's default-branch
# scope can be restored by a later run of that repository (a fork's pull_request run
# included, where Actions lets one run), an artifact is downloadable by anyone signed in
# (limb C), and a job output reaches a step only through an expression, whose value the
# runner prints in the step's public log header. So each hand-off is encrypted and
# authenticated (HMAC-SHA256 in counter mode as the keystream, encrypt-then-MAC, its own
# cache key — run, attempt, job — bound in) BEFORE actions/cache/save, under
# NIKATRU_DETAIL_KEY, held by the hand-off steps and the report job's send step. The
# hand-off steps run pull-request code of the PRIVATE repository, whose authors already
# read its pull requests; the key keeps the detail from everyone else. The worst a
# poisoned hand-off can do to the report job is drop the detail and red that step.
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
# ⏱ 2026-10-05 (p7-shell-fixes, B1): EVERY POST NAMES ITS OWN AGENT. The bridge's route is
# workers.dev, behind Cloudflare's Browser Integrity Check, which refuses Python's default
# `User-Agent: Python-urllib/3.x` with 403 / error code 1010 before the Worker runs. Measured
# from Box A in the P7 rehearsal: that agent 403/1010, a curl agent 401 "bad signature" (it
# reached the Worker), and every report of R1 and R2 was the 403 — no status from the shell.
# post() sends USER_AGENT; the test bridge refuses the default agent exactly as the edge does.
#
# ⏱ 2026-10-06 (ops-followups-1006): A TRANSIENT ANSWER IS RETRIED. Shell run 37430771854
# attempt 2 went red on ONE `ci/lane-workers success -> HTTP 502 (GitHub call failed)` while
# 22 other posts of the same job returned 200. post() retries a 502/503/504 and a post that got
# no answer at all, RETRY_DELAYS seconds apart (2, then 6), then reports the last answer as
# before. Repeating a report is safe: the bridge's POST /report sets a commit status (the
# newest of a context wins) and edits, never duplicates, its marked comment, and the bridge
# itself re-reads by that marker before it re-creates one. Nothing else is retried: a 4xx is
# the bridge's verdict on the report, and a retry cannot change it.
#
# ⏱ 2026-10-06 (followups-r3, PR #16 review finding 2): ONE LAYER'S TIME, NOT TWO STACKED. Each post
# waits the config's `postTimeoutS` (gen-public-shell.mjs REPORT_POST_TIMEOUT_S: the bridge's
# REPORT_BUDGET_MS plus a margin, one source), so a post never gives up on — and re-posts beside —
# a /report that is still running. And a bridge 502 is retried only when its `upstream` (GitHub's
# own answer behind it) is transient too, or absent (the edge's 502): a GitHub 4xx behind a 502 is
# not cured by asking again.
#
# ⏱ 2026-10-08 (gitleaks-pr-scoped-r2, review 26acc3ec finding 2): A GREEN GATE CAN CARRY NOTES. A
# quiet step's `::nikatru-detail::` line lands in its job's detail as a `### NOTE <step>` section on a
# green step too (the quiet-step wrapper), so a job with a note hands a detail over while green.
# Every job's NOTE sections are added to the GATE's detail, and a `success` gate posts those sections
# (and nothing else) as its detail; a lane's success still posts none. The first such note is an
# applied PR-scoped secret-scan exemption (tooling/ci/scan-secrets.mjs), a hole a reviewer must see.
#
# Exit 0 every report accepted (handoff: sealed, or nothing to hand over; collect: the
# bundle written) · 1 a report refused or not delivered (a verdict that did not land
# must not look green) · 2 COVERAGE LOST: no config, no bridge URL, no secret, no sha —
# nothing could be signed or sent; send: a detail bundle that does not unseal (the
# statuses went out without it); handoff: no key or no hand-off key, so nothing handed.
# ─────────────────────────────────────────────────────────────────────────────
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARY_MAX_CHARS = 140
DETAIL_MAX_BYTES = 60 * 1024
CONTEXT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._/():-]{0,99}$')
SHA = re.compile(r'^[0-9a-f]{40}$')
STATE_OF = {'success': 'success', 'failure': 'failure', 'cancelled': 'error'}
# The collect output's cap: it fits one environment variable (Linux caps one at 128 KiB)
# and a job output (1 MB).
SEALED_MAX_CHARS = 120 * 1024
# One hand-off's plain tail: sealed, at least four fit in the collect output; the rest
# that do not fit are named in the gate's detail.
HANDOFF_MAX_BYTES = 16 * 1024
HANDOFF_PREFIX = 'nikatru-detail-'
DETAIL_FILE = 'report-detail.md'
SEALED_FILE = 'detail.sealed'
BUNDLE_VERSION = 2
SEAL_VERSION = b'\x01'
NONCE_BYTES = 16
TAG_BYTES = 32
DETAIL_DIR = '.nikatru-detail'
# A green step's own detail section (the quiet-step wrapper's noteSection).
NOTE_HEADER = '### NOTE '
# The agent every POST to the bridge names (B1): never urllib's default, which the edge bans.
USER_AGENT = 'nikatru-shell-report/1'
COLLECTED_DIR = '.nikatru-collected'
# The answers a retry may cure (a gateway's; 0 is no answer at all), and the waits, in seconds,
# before the second and third attempts.
RETRY_STATUSES = (0, 502, 503, 504)
RETRY_DELAYS = (2, 6)


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
    for k in ('prefix', 'slots', 'gate', 'lanes', 'postTimeoutS'):
        if k not in cfg:
            raise Lost(f'{path} has no `{k}`')
    if not isinstance(cfg['postTimeoutS'], (int, float)) or isinstance(cfg['postTimeoutS'], bool) or cfg['postTimeoutS'] <= 0:
        raise Lost(f'{path}: postTimeoutS {cfg["postTimeoutS"]!r} is not a positive number of seconds')
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


def handoff_key_ok(name, env):
    """True when `name` is a hand-off cache key of this run+attempt: `nikatru-detail-<run>-<attempt>-<member>.<n>`."""
    return bool(re.match(r'^[A-Za-z0-9._-]{1,400}$', name)) and member_of(name, f'{HANDOFF_PREFIX}{run_of(env)}-') is not None


# ── handoff ──────────────────────────────────────────────────────────────────

def handoff(env):
    """Seal this job's red detail for the cache: plain text never reaches actions/cache/save."""
    try:
        with open(os.path.join(env.get('RUNNER_TEMP', ''), DETAIL_FILE), encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        text = ''
    if not text.strip():
        print('-- handoff: no red detail to hand over')
        return 0
    name = env.get('NIKATRU_HANDOFF', '')
    if not handoff_key_ok(name, env):
        raise Lost(f'NIKATRU_HANDOFF {name[:100]!r} is not a hand-off key of this run and attempt: nothing handed over')
    key = env.get('NIKATRU_DETAIL_KEY', '')
    if not key:
        raise Lost('NIKATRU_DETAIL_KEY is not set: the red detail is NOT handed over (it is never cached in plain text)')
    plain = tail_bytes(text, HANDOFF_MAX_BYTES).encode('utf-8')
    os.makedirs(DETAIL_DIR, exist_ok=True)
    with open(os.path.join(DETAIL_DIR, SEALED_FILE), 'w', encoding='ascii') as f:
        f.write(seal(key, name, plain))
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
        f.write('has=true\n')
    print(f'ok handoff: {len(plain)} byte(s) of red detail sealed for {name}')
    return 0


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
    src = os.path.join(DETAIL_DIR, SEALED_FILE)
    if not re.match(r'^[A-Za-z0-9._-]+$', key) or not os.path.isfile(src):
        print(f'x place: no restored detail for {key!r}')
        return 1
    os.makedirs(COLLECTED_DIR, exist_ok=True)
    shutil.move(src, os.path.join(COLLECTED_DIR, f'{key}.sealed'))
    shutil.rmtree(DETAIL_DIR, ignore_errors=True)
    print(f'ok place: {key}')
    return 0


# ── collect ──────────────────────────────────────────────────────────────────

def collected(prefix):
    """{key: sealed text} of this run+attempt's hand-offs in .nikatru-collected/, in key order.
    Carried as they are: this job holds no key, so it can neither read nor reseal them."""
    out = {}
    if not os.path.isdir(COLLECTED_DIR):
        return out
    for name in sorted(os.listdir(COLLECTED_DIR)):
        key = name[:-len('.sealed')] if name.endswith('.sealed') else None
        if key is None or member_of(key, prefix) is None:
            continue
        with open(os.path.join(COLLECTED_DIR, name), encoding='ascii', errors='replace') as f:
            out[key] = f.read().strip()
    return out


def detail_for(members, details):
    # A member is `<workflow>.<job>`; a lane's prefixes end in `.` (`ci.guard-tests.` or a
    # whole called workflow, `lane-workers.`), so `ci.guard-tests` never takes `ci.guard-tests-floor`.
    return join_detail([t for m, texts in details.items() if any(f'{m}.'.startswith(p) for p in members) for t in texts])


def notes_of(detail):
    """The `### NOTE <step>` sections of a detail (the quiet-step wrapper's noteSection): what a step
    said to the private pull request on purpose, green or red."""
    out, keep = [], False
    for line in detail.split('\n'):
        if line.startswith('### '):
            keep = line.startswith(NOTE_HEADER)
        if keep:
            out.append(line)
    return '\n'.join(out).strip('\n')


def build(context, state, env, detail, gate=False):
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
    elif state == 'success' and gate and notes_of(detail):
        # ⏱ 2026-10-08 · gitleaks-pr-scoped-r2: a GREEN gate carries its NOTE sections, and only those.
        body['detail'] = tail_bytes(notes_of(detail), DETAIL_MAX_BYTES)
    return body


def post(url, secret, body, timeout, opener=urllib.request.urlopen, sleep=time.sleep):
    """(status, why) of the report: a transient answer retried, RETRY_DELAYS apart, then the last.
    `timeout` is the config's postTimeoutS: above the bridge's whole budget for one report."""
    raw = json.dumps(body, ensure_ascii=False).encode('utf-8')
    for attempt in range(len(RETRY_DELAYS) + 1):
        status, why, upstream = post_once(url, secret, raw, opener, timeout)
        transient = status in RETRY_STATUSES and (status != 502 or upstream is None or upstream in RETRY_STATUSES)
        if not transient or attempt == len(RETRY_DELAYS):
            return status, why
        print(f'-- HTTP {status} is transient; retrying in {RETRY_DELAYS[attempt]} s', file=sys.stderr)
        sleep(RETRY_DELAYS[attempt])


def post_once(url, secret, raw, opener, timeout):
    """(status, why, upstream): `upstream` is the GitHub status a bridge 502 names, or None."""
    req = urllib.request.Request(url, data=raw, method='POST', headers={
        'content-type': 'application/json',
        'user-agent': USER_AGENT,
        'x-bridge-signature': signature(secret, raw),
    })
    try:
        with opener(req, timeout=timeout) as r:
            return r.status, '', None
    except urllib.error.HTTPError as e:
        why, upstream = '', None
        try:
            answer = json.loads(e.read().decode('utf-8'))
            why = str(answer.get('error', ''))[:200]
            got = answer.get('upstream')
            upstream = got if isinstance(got, int) and not isinstance(got, bool) else None
        except (ValueError, AttributeError):
            pass
        return e.code, why, upstream
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)[:200], None


def collect(env, cfg):
    """The sealed hand-offs, carried through unchanged as one bundle within SEALED_MAX_CHARS;
    the restore slots' overflow and any hand-off that does not fit are named, not carried."""
    prefix = run_prefix(cfg, env)
    handed = collected(prefix)
    unrestored = [k for k in env.get('NIKATRU_OVERFLOW', '').split(',') if k and member_of(k, prefix)]
    bundle = {'v': BUNDLE_VERSION, 'handoffs': {}, 'unrestored': unrestored}
    for key, sealed in handed.items():
        bundle['handoffs'][key] = sealed
        if len(json.dumps(bundle, separators=(',', ':'))) > SEALED_MAX_CHARS - 1024:
            del bundle['handoffs'][key]
            bundle['unrestored'].append(key)
    text = json.dumps(bundle, separators=(',', ':'))
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
        f.write('detail=' + (text if handed or unrestored else '') + '\n')
    print(f'ok collect: {len(bundle["handoffs"])} sealed hand-off(s) carried, {len(bundle["unrestored"])} named only')
    return 0


# ── send ─────────────────────────────────────────────────────────────────────

def received_details(env, cfg):
    """({context: detail}, lost): the bundle nikatru-collect handed over, each hand-off unsealed
    under its own key and checked. It is data: parsed as JSON, never run, imported or written
    out. `lost` names why a bundle that was handed over could not be read: the reports then
    go out without detail and the send exits 2 (COVERAGE LOST), never an empty pass."""
    raw = env.get('NIKATRU_DETAIL', '')
    if not raw:
        print('-- detail: none handed over; the reports go out without detail')
        return {}, None
    try:
        return read_bundle(raw, env, cfg), None
    except Refused as e:
        return {}, f'the red detail could not be read: {e}; the reports went out without detail'
    except Exception as e:  # whatever a hand-off does, the statuses still go out
        return {}, f'the red detail could not be read ({type(e).__name__}); the reports went out without detail'


def read_bundle(raw, env, cfg):
    if len(raw) > SEALED_MAX_CHARS:
        raise Refused(f'{len(raw)} characters, over the {SEALED_MAX_CHARS} cap')
    try:
        bundle = json.loads(raw)
    except Exception as e:  # RecursionError (deep nesting) is a RuntimeError, not a ValueError
        raise Refused(f'not JSON this reporter can read ({type(e).__name__})')
    if not isinstance(bundle, dict) or bundle.get('v') != BUNDLE_VERSION or not isinstance(bundle.get('handoffs'), dict) or not isinstance(bundle.get('unrestored'), list):
        raise Refused(f'not a version-{BUNDLE_VERSION} hand-off bundle')
    prefix = run_prefix(cfg, env)
    key = env.get('NIKATRU_DETAIL_KEY', '')
    if bundle['handoffs'] and not key:
        raise Refused('NIKATRU_DETAIL_KEY is not set')
    details = {}
    for name, sealed in bundle['handoffs'].items():
        member = member_of(name, prefix) if re.match(r'^[A-Za-z0-9._-]{1,400}$', name) else None
        if member is None or not isinstance(sealed, str):
            raise Refused(f'{name[:100]!r} is not a hand-off of this run and attempt')
        try:
            plain = unseal(key, name, sealed)
        except Refused as e:
            raise Refused(f'hand-off {name!r}: {e}')
        if len(plain) > HANDOFF_MAX_BYTES:
            raise Refused(f'hand-off {name!r} is over the {HANDOFF_MAX_BYTES}-byte cap')
        details.setdefault(member, []).append(plain.decode('utf-8', errors='replace'))
    unrestored = [member_of(k, prefix) for k in bundle['unrestored'] if isinstance(k, str)]
    if None in unrestored or len(unrestored) != len(bundle['unrestored']):
        raise Refused('it names an unrestored hand-off that is not this run\'s')
    # Every job's NOTE sections ride on the gate's detail too: the gate's members are its own job,
    # and a note (an applied PR-scoped secret-scan exemption) is said where the reviewer looks.
    notes = notes_of(join_detail([t for texts in details.values() for t in texts]))
    out = {}
    for item in list(cfg['lanes']) + [cfg['gate']]:
        detail = detail_for(item['members'], details)
        if item is cfg['gate'] and notes and notes not in detail:
            detail = join_detail([detail, notes])
        if item is cfg['gate'] and unrestored:
            detail += '\n\n(' + str(len(unrestored)) + ' more red job(s) handed over detail this report could not carry: ' + ', '.join(unrestored) + ')\n'
        if detail.strip():
            out[item['context']] = detail
    return out


def gate_origin_ok(env, cfg=None):
    """True when this run may report the gate: a pull request with a number, or a push to main or of a tag.
    A workflow the generator marks `leadDispatch` (2026-10-06, bridge-train-1006: e2e.yml against a PR head)
    may also report it for a `workflow_dispatch`-origin dispatch of a branch: the PR head it was sent for."""
    event = env.get('NIKATRU_P_EVENT', '')
    ref = env.get('NIKATRU_P_REF', '')
    if event == 'pull_request':
        return re.fullmatch(r'[1-9][0-9]{0,9}', env.get('NIKATRU_P_PR', '')) is not None
    if event == 'workflow_dispatch' and (cfg or {}).get('leadDispatch') is True:
        return ref.startswith('refs/heads/')
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
    details, lost = received_details(env, cfg)
    failed = 0
    for item in list(cfg['lanes']) + [cfg['gate']]:
        state = STATE_OF.get(results.get(item['job'], ''))
        if state is None:
            print(f"-- {item['context']}: {results.get(item['job'], 'absent')}, not reported")
            continue
        if item is cfg['gate'] and not gate_origin_ok(env, cfg):
            failed += 1
            print(f"x  {item['context']}: NOT reported — this run is not a pull request, main or a tag run (nor a lead dispatch its config allows) "
                  f"(event {env.get('NIKATRU_P_EVENT', '')!r}, ref {env.get('NIKATRU_P_REF', '')!r}); only such a run may write the gate")
            continue
        status, why = post(url, secret, build(item['context'], state, env, details.get(item['context'], ''), item is cfg['gate']), cfg['postTimeoutS'], opener)
        ok = 200 <= status < 300
        failed += 0 if ok else 1
        print(f"{'ok' if ok else 'x '} {item['context']} {state} -> HTTP {status}{f' ({why})' if why and not ok else ''}")
    # Every status was attempted: the report job's fallback step (no detail) need not run.
    if env.get('GITHUB_OUTPUT'):
        with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write('reported=true\n')
    if lost:
        print(f'x COVERAGE LOST - report.py: {lost}', file=sys.stderr)
        return 2
    return 1 if failed else 0


def main(argv, env):
    try:
        if len(argv) == 1 and argv[0] == 'handoff':
            return handoff(env)
        if len(argv) == 2 and argv[0] == 'place':
            return place(argv[1])
        if len(argv) == 2 and argv[0] in ('plan', 'collect', 'send'):
            cfg = load_config(argv[1])
            return {'plan': plan, 'collect': collect, 'send': send}[argv[0]](env, cfg)
        print('usage: report.py handoff | plan <config> | place <key> | collect <config> | send <config>', file=sys.stderr)
        return 2
    except Lost as e:
        print(f'x COVERAGE LOST - report.py: {e}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], os.environ))
