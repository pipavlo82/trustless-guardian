"""Resonance Agent v1: read-only, bounded, auditable environmental agent.
No LLM, tool execution, privileged operations or background service.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, math, os, time
from dataclasses import dataclass, asdict
from pathlib import Path
import psutil

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "agent_events.jsonl"
STATE = ROOT / "agent_state.json"
FIELDS = ("cpu", "memory", "disk", "hour_sin", "hour_cos", "solar_proxy", "lunar_proxy")
WEIGHTS = {"cpu":.26, "memory":.18, "disk":.14, "hour_sin":.08,
           "hour_cos":.08, "solar_proxy":.13, "lunar_proxy":.13}

def clip(x):
    return max(0.0, min(1.0, float(x)))

def measure():
    # Local system signals are observed; astronomical channels are illustrative
    # time-phase proxies, NOT ephemerides or actual solar/lunar measurements.
    now = dt.datetime.now(dt.timezone.utc)
    hour = (now.hour*3600+now.minute*60+now.second)/86400
    lunar = ((now.timestamp()/86400) % 29.53059)/29.53059
    return {
        "cpu": clip(psutil.cpu_percent(interval=.1)/100),
        "memory": clip(psutil.virtual_memory().percent/100),
        "disk": clip(psutil.disk_usage(str(ROOT.anchor)).percent/100),
        "hour_sin": clip((math.sin(2*math.pi*hour)+1)/2),
        "hour_cos": clip((math.cos(2*math.pi*hour)+1)/2),
        "solar_proxy": clip((math.sin(2*math.pi*hour)+1)/2),
        "lunar_proxy": clip((math.cos(2*math.pi*lunar)+1)/2),
    }

@dataclass
class State:
    step: int = 0
    attention: float = .5
    energy: float = .5
    phase: float = 0.0
    previous_hash: str = "GENESIS"
    previous_signals: dict | None = None

def decide(state, signals):
    if set(signals) != set(FIELDS): raise ValueError("Unexpected signal schema")
    if not all(isinstance(v,(int,float)) and math.isfinite(v) and 0<=v<=1 for v in signals.values()):
        raise ValueError("Signals must be finite normalized floats")
    prev = state.previous_signals or signals
    novelty = sum(WEIGHTS[k]*abs(signals[k]-prev[k]) for k in FIELDS)
    pressure = .5*signals["cpu"]+.3*signals["memory"]+.2*signals["disk"]
    attention = clip(.78*state.attention + .22*(.2+.8*novelty))
    energy = clip(state.energy + .08*(1-pressure)-.11*pressure)
    phase = (state.phase + .4 + novelty*1.2) % (2*math.pi)
    if pressure > .88: action="DEFER"
    elif novelty > .20: action="INVESTIGATE_CHANGE"
    elif attention > .60: action="REVIEW"
    else: action="OBSERVE"
    new=State(state.step+1,attention,energy,phase,state.previous_hash,dict(signals))
    return new, {"action":action,"novelty":round(novelty,6),"pressure":round(pressure,6)}

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),allow_nan=False)

def make_record(state,signals,decision,utc):
    rec={"seq":state.step,"utc":utc,"signals":signals,"decision":decision,
         "attention":round(state.attention,6),"energy":round(state.energy,6),
         "phase":round(state.phase,6),"previous_hash":state.previous_hash}
    rec["hash"]=hashlib.sha256(canonical(rec).encode()).hexdigest()
    return rec

def verify(path):
    previous="GENESIS"; n=0
    for line in path.read_text(encoding="utf-8").splitlines():
        rec=json.loads(line)
        h=rec.pop("hash")
        if rec["previous_hash"]!=previous or hashlib.sha256(canonical(rec).encode()).hexdigest()!=h:
            raise ValueError(f"Invalid hash chain at record {n+1}")
        if rec["seq"]!=n+1: raise ValueError("Sequence discontinuity")
        previous=h;n+=1
    return {"verified":True,"records":n,"last_hash":previous}

def run(steps,interval,synthetic=False):
    if steps<1 or steps>1000 or not 0<=interval<=60:raise ValueError("Invalid bounds")
    if LOG.exists() or STATE.exists():
        raise RuntimeError("Existing log/state: use a new output directory or archive before a fresh run")
    state=State()
    with LOG.open("x",encoding="utf-8") as f:
        for i in range(steps):
            if synthetic:
                signals={k:clip(.4+.3*math.sin(i*.7+j)) for j,k in enumerate(FIELDS)}
            else: signals=measure()
            state,decision=decide(state,signals)
            rec=make_record(state,signals,decision,dt.datetime.now(dt.timezone.utc).isoformat())
            f.write(canonical(rec)+"\n");f.flush()
            state.previous_hash=rec["hash"]
            print(canonical({"seq":rec["seq"],"action":decision["action"],"hash":rec["hash"][:16]}),flush=True)
            if i<steps-1:time.sleep(interval)
    STATE.write_text(canonical(asdict(state)),encoding="utf-8")
    print(canonical(verify(LOG)))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--steps",type=int,default=5)
    p.add_argument("--interval",type=float,default=0.2)
    p.add_argument("--synthetic",action="store_true")
    p.add_argument("--verify",action="store_true")
    a=p.parse_args()
    if a.verify:print(canonical(verify(LOG)))
    else:run(a.steps,a.interval,a.synthetic)
