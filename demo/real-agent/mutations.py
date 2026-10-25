"""Real model-driven mutation campaign, with fresh restored positive controls."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import time
from mutation_spec import MUTATIONS, classify

HERE = Path(__file__).resolve().parent


def write(p, v): p.write_bytes(json.dumps(v, sort_keys=True, indent=2).encode()+b'\n')


def run(out, runtime):
    out = out.absolute(); out.mkdir(parents=True, exist_ok=False); commands = []; results = []
    def execute(name, mutant=None):
        path = out/name
        argv = [sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(HERE/'run.py'),'--runtime',str(runtime),'--out',str(path)]
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
        result = {'mutation':name,'target':target,'classification':classify(base,changed,restored,target,exact,applied),
                  'physical_restoration':exact,'target_changed':bool(changed and changed['checks'].get(target) is False)}
        results.append(result); print(json.dumps(result),flush=True); base = restored
        write(out/'report.json', {'population':'v06-real-model-tools','mutations':results,'counts':dict(Counter(r['classification'] for r in results)),'commands':commands})
    return results


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True);a=p.parse_args()
    results=run(a.out,a.runtime.resolve());raise SystemExit(any(r['classification']!='KILLED' for r in results))
