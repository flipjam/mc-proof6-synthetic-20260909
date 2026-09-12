"""Independent-style reproduction of the five bounded reviewer counterexamples.

Literal inert records; production entry points; no prior test/fixture imports.
No unshare, network request or real child process is executed.
"""
import json
import os
from pathlib import Path
import sys
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import d04_capability as cap
import d04_prerequisite as pre


def context(pid):
    return dict(pid=pid,euid=0,kernel='6.17.0-1022-azure',cap_eff='000001ffffffffff',
        cap_sys_admin=True,seccomp=0,lsm='unconfined',netns='net:[4026531833]',
        runner=dict(RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Linux',
                    RUNNER_ARCH='X64',ImageOS='ubuntu24',ImageVersion='20260907.300.1'))


def null_child():
    return dict(schema='PROOF6_R3G_D04_CAPABILITY_V1',stage='QUALIFIED',qualified=True,
        acceptance_credit=False,context=context(os.getpid()+1),libc_loaded=True,
        unshare=dict(return_code=0,errno=0,errno_name='NONE'),netns_after=None,
        interfaces=['lo'],ipv4=dict(read_success=True,header_present=False,
            header_valid=False,entry_count=0,valid=True,qualified=True),
        ipv6=dict(read_success=True,entry_count=0,interfaces=[],valid=True,qualified=True),
        connectivity=dict(connected=False,exception=dict(type='gaierror',errno=-3)),
        exception=None,elapsed_seconds=0.001)


def prerequisite_rejects():
    proc=Mock(returncode=0)
    proc.__enter__=Mock(return_value=proc);proc.__exit__=Mock(return_value=None)
    proc.communicate.return_value=(json.dumps(null_child()).encode(),None)
    with patch.object(cap,'context',return_value=context(os.getpid())), \
         patch.object(pre.subprocess,'Popen',return_value=proc):
        return pre.run()['qualified'] is False


def setup_rejects():
    receipt=dict(schema='PROOF6_R3G_D04_PREREQUISITE_V1',stage='PREREQUISITE_PASS',
        qualified=True,acceptance_credit=False,parent_before=context(os.getpid()),
        parent_after=context(os.getpid()),child=null_child(),supervisor_exit=0,
        child_reaped=True,exception=None)
    try:
        pre.setup_qualification(json.dumps(receipt))
    except (ValueError,TypeError,KeyError):
        return True
    return False


def reproduce():
    header='Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT'
    row=('00000000000000000000000000000000 00 '
         '00000000000000000000000000000000 00 '
         '00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n')
    return {
        'ipv4_header_U001F':cap.ipv4(header+'\x1f')['qualified'] is False,
        'ipv4_header_U001E':cap.ipv4(header+'\x1e')['qualified'] is False,
        'null_changed_namespace_prerequisite':prerequisite_rejects(),
        'null_setup_qualification':setup_rejects(),
        'ipv6_U001F_separators':cap.ipv6(row.replace(' ','\x1f'))['qualified'] is False,
    }


if __name__=='__main__':
    result=reproduce()
    print(json.dumps(dict(counterexamples=result,all_five_rejected=all(result.values())),sort_keys=True,indent=2))
    sys.exit(0 if all(result.values()) else 1)
