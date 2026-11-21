"""Pinned, additive stack transition. Historical inventory/checkers remain unchanged."""
from pathlib import Path
import argparse, hashlib, json, subprocess

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'research/stack_ci_transition_v1/INVENTORY.json'
WORKFLOW = '.github/workflows/guardian.yml'
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'

class Refusal(ValueError): pass

def digest(raw): return hashlib.sha256(raw).hexdigest()
def git(root, *args): return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.PIPE)
def tree(root, commit):
    answer = {}; entries=[]
    for item in git(root, 'ls-tree', '-rz', commit).split(b'\0'):
        if not item: continue
        meta, name = item.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        if kind != 'blob' or mode not in ('100644', '100755'): raise Refusal('UNSUPPORTED_GIT_ENTRY')
        entries.append((name.decode(),oid))
    p=subprocess.run(['git','cat-file','--batch'],cwd=root,input=('\n'.join(oid for _,oid in entries)+'\n').encode(),capture_output=True,check=True)
    offset=0
    for name,oid in entries:
        end=p.stdout.index(b'\n',offset);header=p.stdout[offset:end].decode().split()
        if header[:2]!=[oid,'blob']:raise Refusal('GIT_OBJECT_MISMATCH')
        size=int(header[2]);start=end+1;answer[name]=digest(p.stdout[start:start+size]);offset=start+size+1
    if offset!=len(p.stdout):raise Refusal('GIT_BATCH_TRAILING_DATA')
    return answer

def verify(root, pin):
    root = Path(root).resolve()
    raw = (root/POLICY).read_bytes()
    if digest(raw) != pin: raise Refusal('POLICY_PIN_MISMATCH')
    policy = json.loads(raw)
    if policy['schema'] != 'guardian.stack-ci-transition.v1' or policy['frozen_sha'] != FROZEN: raise Refusal('POLICY_IDENTITY')
    historical = tree(root, FROZEN)
    upstream = tree(root, policy['source_sha'])
    if historical != policy['frozen_files'] or upstream != policy['source_files']: raise Refusal('HISTORICAL_IDENTITY')
    if git(root, 'merge-base', FROZEN, policy['source_sha']).decode().strip() != FROZEN: raise Refusal('SOURCE_ANCESTRY')
    if any(upstream.get(name) != value for name, value in historical.items()): raise Refusal('HISTORICAL_REPLACEMENT')
    additions = {name:value for name,value in upstream.items() if name not in historical}
    if additions != policy['research_additions'] or len(additions) != policy['research_addition_count']: raise Refusal('RESEARCH_EXTENSION')
    if set(policy['changed']) != {'README.md', WORKFLOW}: raise Refusal('UNAPPROVED_TRANSITION')
    if any(name in upstream for name in policy['added']): raise Refusal('ADDITION_OVERWRITES_HISTORY')
    expected = {**upstream, **policy['changed'], **policy['added']}
    if POLICY in expected: raise Refusal('SELF_REFERENTIAL_POLICY')
    names = {name.decode() for name in git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').split(b'\0') if name}
    if names != set(expected) | {POLICY}: raise Refusal('PATH_SET_MISMATCH')
    if git(root, 'ls-files', '-u'): raise Refusal('UNRESOLVED_INDEX')
    for name, value in expected.items():
        path = root/name
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file(): raise Refusal('MISSING_OR_REDIRECTED:'+name)
        content = path.read_bytes()
        if name == WORKFLOW:
            needle = pin.encode()
            if content.count(needle) != 1: raise Refusal('WORKFLOW_PIN_BINDING')
            content = content.replace(needle, b'__POLICY_SHA256__')
        if digest(content) != value: raise Refusal('CONTENT_MISMATCH:'+name)
    return {'status':'VERIFIED_TRANSITION','schema':policy['schema'],'source_sha':policy['source_sha'],
            'historical_files':len(historical),'research_additions':len(additions),'current_files':len(expected)+1,
            'historical_raw_checker':'REPLAY_AT_EXACT_FROZEN_SHA','production':'HOLD'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--pin',required=True);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
    try: result=verify(a.root,a.pin)
    except (Refusal,OSError,KeyError,ValueError,subprocess.CalledProcessError) as e:
        print(json.dumps({'status':'REFUSED','reason':str(e)},sort_keys=True));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
