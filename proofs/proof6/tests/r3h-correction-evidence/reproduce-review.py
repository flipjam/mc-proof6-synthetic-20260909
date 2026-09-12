import ast,json,os,socket,sys,types
from pathlib import Path
sys.path.insert(0,'proofs/proof6')
import d04_signal as corrected
source=Path(sys.argv[1]).read_bytes()
previous=types.ModuleType('partial_signal');previous.__file__=str(Path('proofs/proof6/d04_signal.py').resolve())
exec(compile(source,'partial 032076f d04_signal.py','exec'),previous.__dict__)
from importlib import util
spec=util.spec_from_file_location('fixtures','proofs/proof6/tests/d04_fixtures.py');f=util.module_from_spec(spec);spec.loader.exec_module(f)
import array
record=f.child();b=dict(run_id=123,attempt=1,runtime_sha='a'*40,target_sha='a'*40,context='proof6/d04-signal/123/1/'+'a'*40)
event=dict(schema=previous.SCHEMA,binding=b,pid=record['context']['pid'],phase='READY',monotonic=previous.time.monotonic(),utc=previous.utc(),observation=record)
results={'source':'032076ffbcd1056c3f8f99d096e07214421e13c9','kernel':os.uname().release,'acceptance_credit':False}
for label,module in [('partial',previous),('corrected',corrected)]:
 a,c=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);fd=os.open('/dev/null',os.O_RDONLY)
 c.sendmsg([module.canonical(event)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
 try:
  value=module.receive(a);module.event_valid(value,b,event['pid'],'READY');accepted=True
 except ValueError:accepted=False
 a.close();c.close();os.close(fd);results[label+'_A_accepted']=accepted
 a,c=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);c.send(b'')
 try:
  if label=='partial':accepted=a.recv(1)==b''
  else:module.peer_shutdown(a);accepted=True
 except ValueError:accepted=False
 results[label+'_B_accepted']=accepted;results[label+'_B_peer_still_open']=c.fileno()>=0
 a.close();c.close()
print(json.dumps(results,sort_keys=True,indent=2))
assert results['partial_A_accepted'] and results['partial_B_accepted']
assert not results['corrected_A_accepted'] and not results['corrected_B_accepted']
