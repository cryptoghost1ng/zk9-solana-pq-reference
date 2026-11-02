"""Operator health check for the relay service (a draft of gate G9: there was no monitoring at all). It reads ONLY what the service already writes in its state directory
(EVENTS.jsonl, requests/, outcomes/) and, if asked, the sponsor's balance from the validator/cluster RPC named in the live configuration. It sends nothing anywhere else, changes nothing,
and prints ONE JSON line. Exit code: 0 OK, 1 WARN, 2 CRIT (so cron/launchd can act on it; wiring a notification is left to the operator).
What it can tell from the events: whether the service is running (last `ready` not followed by `stopped`/`fatal`), whether a request is parked or has failing steps since the last start, whether an unfinished
request has gone quiet, and (with the RPC) whether the sponsor balance is under a floor. What it cannot tell: that the Tor onion service is reachable, or that the service is still alive after its last event
(it has no heartbeat yet: `--max-quiet-min` only looks at an unfinished request). It is tested on archived events and on a live run, not on a real deployment.
usage: operator_health.py STATE_DIR [LIVE_CONFIG.json] [--min-sol 40] [--max-quiet-min 20]"""
import json,sys,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
argv=sys.argv[1:];args=[];i=0
while i<len(argv):                      # positional arguments; every --flag takes one value
    if argv[i].startswith('--'):i+=2
    else:args.append(argv[i]);i+=1
def opt(name,default):return float(argv[argv.index(name)+1]) if name in argv else default
assert 1<=len(args)<=2,__doc__
state=Path(args[0]);config=Path(args[1]) if len(args)==2 else None
min_sol=opt('--min-sol',40.0);max_quiet=opt('--max-quiet-min',20.0)
now=datetime.now(timezone.utc);report={'checked_at':now.isoformat(timespec='seconds'),'state':'OK','problems':[],'warnings':[]}
def problem(code,**k):report['problems'].append({'code':code,**k})
def warn(code,**k):report['warnings'].append({'code':code,**k})
events=[]
try:
    for line in (state/'EVENTS.jsonl').read_text().splitlines():
        try:events.append(json.loads(line))
        except ValueError:pass
except OSError as exc:
    problem('no_event_log',detail=str(exc)[:120])
iso=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
ready=[i for i,e in enumerate(events) if e.get('type')=='ready']
if events and not ready:problem('service_never_reported_ready')
if ready:
    since=events[ready[-1]:];last=since[-1]
    report['authority']=since[0].get('authority');report['last_ready']=since[0].get('t');report['last_event']={'type':last.get('type'),'t':last.get('t')}
    if any(e.get('type') in ('stopped','fatal') for e in since):problem('service_not_running',last=last.get('type'))
    errors=[e for e in since if e.get('type')=='task_error'];report['task_errors_since_start']=len(errors)
    parked={e['id'] for e in since if e.get('type')=='parked'}
    done={e['id'] for e in since if e.get('type') in ('finished',)}
    for pid in sorted(parked-done):problem('request_parked',id=pid[:16])
    if errors and not parked:warn('steps_failing',count=len(errors),last=errors[-1].get('message','')[:100])
    refused=[e for e in since if e.get('type')=='refused'];report['refused_since_start']=len(refused)
# unfinished requests (a request file without an outcome) that went quiet
unfinished=[]
try:
    outcomes={p.name for p in (state/'outcomes').iterdir()} if (state/'outcomes').is_dir() else set()
    for p in (state/'requests').iterdir():
        if p.suffix=='.request' and p.stem not in outcomes and (p.stem not in {o.split('.')[0] for o in outcomes}):unfinished.append(p.stem)
except OSError:pass
report['unfinished_requests']=len(unfinished)
if unfinished and events:
    quiet=(now-iso(events[-1]['t'])).total_seconds()/60;report['minutes_since_last_event']=round(quiet,1)
    if quiet>max_quiet:problem('unfinished_request_gone_quiet',minutes=round(quiet,1),requests=[u[:16] for u in unfinished])
if config is not None and report.get('authority'):
    try:
        cfg=json.loads(config.read_text());endpoint=cfg['network']['endpoint']
        req=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':'getBalance','params':[report['authority'],{'commitment':'confirmed'}]}).encode(),headers={'content-type':'application/json'})
        with urllib.request.urlopen(req,timeout=20) as r:balance=json.loads(r.read())['result']['value']
        report['sponsor_balance_sol']=round(balance/1e9,4)
        if balance/1e9<min_sol:problem('sponsor_balance_below_floor',floor_sol=min_sol)
    except Exception as exc:
        warn('balance_unavailable',detail=repr(exc)[:120])
report['state']='CRIT' if report['problems'] else 'WARN' if report['warnings'] else 'OK'
print(json.dumps(report));sys.exit({'OK':0,'WARN':1,'CRIT':2}[report['state']])
