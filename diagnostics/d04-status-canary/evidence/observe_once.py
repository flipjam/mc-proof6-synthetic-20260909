"""One authorized diagnostic dispatch; read-only external live observer afterward."""
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parent
REPO = 'flipjam/mc-proof6-synthetic-20260909'
BASE = 'repos/' + REPO
SHA = '2b7d0fa62e41bc500f6bf2dc5c540910501cabc3'
BRANCH = 'codex/proof6-r3h-live-status-canary-20260912-01'

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def record(item):
    with (ROOT/'observer-polls.jsonl').open('a', encoding='utf-8') as f:
        f.write(json.dumps(item, sort_keys=True) + '\n'); f.flush(); os.fsync(f.fileno())

def get(path):
    start = utc()
    p = subprocess.run(['gh','api','--include','-H','Cache-Control: no-cache',path], capture_output=True, text=True, timeout=15)
    finish = utc()
    if p.returncode:
        record({'path':path,'started_at':start,'completed_at':finish,'error':p.stderr})
        raise RuntimeError('OBSERVER_HTTP_FAILURE')
    head, body = p.stdout.split('\n\n', 1)
    lines = head.splitlines()
    assert re.match(r'HTTP/\S+ 200', lines[0]), lines[0]
    headers = dict((k.strip().lower(), v.strip()) for k,v in (x.split(':',1) for x in lines[1:] if ':' in x))
    data = json.loads(body)
    item = {'path':path,'started_at':start,'completed_at':finish,'http':lines[0],
            'headers':{k:headers.get(k) for k in ('date','x-github-request-id','etag','link')},'body':data}
    record(item)
    return data, item

def main():
    state = {'target_sha':SHA,'branch':BRANCH,'acceptance_credit':False,'observer':'Dev-machine gh CLI; no workflow token',
             'started_at':utc(),'ready':None,'end':None,'run_id':None,'job_id':None}
    try:
        # These successful reads precede the only dispatch.
        runs,_ = get(BASE+'/actions/runs?per_page=5')
        assert runs['workflow_runs'][0]['run_number'] == 47
        statuses,_ = get(BASE+f'/commits/{SHA}/statuses?per_page=100')
        assert statuses == []
        with (ROOT/'dispatch-once.json').open('x',encoding='utf-8') as f:
            json.dump({'target':SHA,'branch':BRANCH,'started_at':utc(),'dispatch_attempts':1},f)
        state['dispatch_started_at'] = utc()
        p = subprocess.run(['gh','workflow','run','354612007','--repo',REPO,'--ref',BRANCH],capture_output=True,text=True,timeout=30)
        state['dispatch_completed_at'] = utc();state['dispatch_exit_code']=p.returncode
        record({'kind':'DISPATCH_ONCE','started_at':state['dispatch_started_at'],'completed_at':state['dispatch_completed_at'],
                'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        assert p.returncode == 0
        print('DISPATCHED_ONCE',SHA,flush=True)
        deadline = time.monotonic()+300
        while time.monotonic()<deadline:
            if state['run_id'] is None:
                runs,_ = get(BASE+'/actions/runs?per_page=5')
                new = [r for r in runs['workflow_runs'] if r['run_number']>47]
                assert len(new)<=1
                if not new:
                    time.sleep(1);continue
                run=new[0]
                assert run['head_sha']==SHA and run['head_branch']==BRANCH and run['event']=='workflow_dispatch'
                assert run['workflow_id']==354612007 and run['run_attempt']==1 and run['run_number']==48
                state['run_id']=run['id'];state['context']=f"proof6/d04-signal-canary/{run['id']}/1/{SHA}"
                print('RUN',run['id'],flush=True)
            statuses,observation = get(BASE+f'/commits/{SHA}/statuses?per_page=100')
            assert not observation['headers']['link']
            assert len(statuses)<=2
            for s in statuses:
                assert s['context']==state['context'] and s['creator']['login']=='github-actions[bot]'
                assert s['target_url']==f"https://github.com/{REPO}/actions/runs/{state['run_id']}"
                assert s['state'] in ('pending','success')
                phase='READY' if s['state']=='pending' else 'END'
                assert re.fullmatch(rf"{phase} r={state['run_id']} a=1 sha={SHA} p=[1-9][0-9]*",s['description'])
            run,run_observation=get(BASE+f"/actions/runs/{state['run_id']}")
            jobs,job_observation=get(BASE+f"/actions/runs/{state['run_id']}/jobs?per_page=100")
            assert jobs['total_count']<=1 and run['head_sha']==SHA and run['run_attempt']==1
            job=jobs['jobs'][0] if jobs['jobs'] else None
            if job:
                assert job['name']=='canary';state['job_id']=job['id']
            ready=[s for s in statuses if s['state']=='pending'];end=[s for s in statuses if s['state']=='success']
            assert len(ready)<=1 and len(end)<=1
            if ready and state['ready'] is None:
                assert not end, 'READY_FIRST_OBSERVED_WITH_END'
                assert job and run['status']=='in_progress' and job['status']=='in_progress'
                state['ready']={'status':ready[0],'observed_at':observation['completed_at'],
                    'provider_headers':observation['headers'],'run_status':run['status'],'job_status':job['status'],
                    'run_state_observed_at':run_observation['completed_at'],'job_state_observed_at':job_observation['completed_at']}
                print('READY_LIVE',json.dumps(state['ready']),flush=True)
            if end and state['end'] is None:
                assert state['ready'] and job and run['status']=='in_progress' and job['status']=='in_progress'
                assert end[0]['description'].split(' p=')[1]==state['ready']['status']['description'].split(' p=')[1]
                state['end']={'status':end[0],'observed_at':observation['completed_at'],
                    'provider_headers':observation['headers'],'run_status':run['status'],'job_status':job['status'],
                    'run_state_observed_at':run_observation['completed_at'],'job_state_observed_at':job_observation['completed_at']}
                print('END_LIVE',json.dumps(state['end']),flush=True)
            if run['status']=='completed':
                assert state['ready'] and state['end'] and job and job['status']=='completed'
                assert run['conclusion']==job['conclusion']=='success'
                assert job['completed_at']>state['end']['observed_at'][:19]+'Z'
                state['final_run']=run;state['final_job']=job
                state['live_sequence']='OBSERVED_PENDING_POSTRUN_SAFETY_REVIEW'
                break
            time.sleep(1)
        else:
            raise TimeoutError('OBSERVER_DEADLINE')
    except Exception as exc:
        state['live_sequence']='FAIL_OR_BLOCKED'
        state['failure']={'type':type(exc).__name__,'message':str(exc)}
        print('OBSERVER_STOP',json.dumps(state['failure']),flush=True)
    finally:
        state['finished_at']=utc()
        (ROOT/'observer-summary.json').write_text(json.dumps(state,sort_keys=True,indent=2),encoding='utf-8')
    print('OBSERVER_RESULT',state['live_sequence'],flush=True)

if __name__=='__main__':
    main()
