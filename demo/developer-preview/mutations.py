"""Deterministic OS mutation campaign, NO model inference, with fresh restored positive controls."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'real-agent'))
from mutation_spec import MUTATIONS, classify as historical_classify, divergence

HERE = Path(__file__).resolve().parent


def classify(base, changed, restored, target, exact, applied, observed=None):
    result = historical_classify(base, changed, restored, target, exact, applied, observed)
    if result == 'KILLED' and any(not v for k, v in changed['checks'].items()
            if k.endswith(('_vector_tool_binding', '_v1_request', '_v1_response', '_no_model_substitution'))):
        return 'CONTROL_BROKEN'
    return result


def write(p, v): p.write_bytes(json.dumps(v, sort_keys=True, indent=2).encode()+b'\n')


def run(out):
    out = out.absolute(); out.mkdir(parents=True, exist_ok=False); commands = []; results = []
    def execute(name, mutant=None):
        path = out/name
        argv = [sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(HERE/'run.py'),'--mode','deterministic','--out',str(path)]
        if mutant: argv += ['--mutation',mutant]
        start = time.perf_counter(); p = subprocess.run(argv,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout); (out/(name+'.stderr')).write_bytes(p.stderr)
        commands.append({'argv':argv,'exit_code':p.returncode,'seconds':time.perf_counter()-start})
        return json.loads((path/'report.json').read_bytes()) if (path/'report.json').exists() else None
    base = execute('baseline')
    for name, (_, _, _, target) in MUTATIONS.items():
        changed = execute(name+'-mutated',name)
        restored = execute(name+'-restored')
        applied_file = out/(name+'-mutated')/'physical-mutation.json'
        restored_file = out/(name+'-mutated')/'physical-restoration.json'
        applied = applied_file.exists() and json.loads(applied_file.read_bytes())['applied']
        exact = restored_file.exists() and json.loads(restored_file.read_bytes())['exact']
        observation_file = out/(name+'-mutated')/'observations.json'
        observed = json.loads(observation_file.read_bytes()) if observation_file.exists() else None
        result = {'mutation':name,'target':target,'classification':classify(base,changed,restored,target,exact,applied,observed),
                  'unsafe_behavior_observed':divergence(observed,target),
                  'physical_restoration':exact,'target_changed':bool(changed and changed['checks'].get(target) is False)}
        results.append(result); print(json.dumps(result),flush=True); base = restored
        write(out/'report.json', {'population':'v07-deterministic-os-controls','mutations':results,'counts':dict(Counter(r['classification'] for r in results)),'commands':commands})
    return results


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    results=run(a.out);raise SystemExit(any(r['classification']!='KILLED' for r in results))
