"""Inert Linux observations. IPv6 raw rows are authored, not retained hosted bytes."""
import copy
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import d04_capability as cap
import d04_prerequisite as pre


def context(pid=None):
    return dict(pid=os.getpid() if pid is None else pid, euid=0,
        kernel='6.17.0-1022-azure', cap_eff='000001ffffffffff', cap_sys_admin=True,
        seccomp=0, lsm='unconfined', netns='net:[4026531833]',
        runner=dict(RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
                    RUNNER_ARCH='X64', ImageOS='ubuntu24', ImageVersion='20260907.300.1'))


def route6(dest=cap.ZERO, prefix='00', src=cap.ZERO, src_prefix='00',
           hop=cap.ZERO, flags='00200200', interface='lo'):
    return f'{dest} {prefix} {src} {src_prefix} {hop} ffffffff 00000001 00000000 {flags} {interface}\n'


def child():
    return dict(schema=cap.SCHEMA, stage='QUALIFIED', qualified=True, acceptance_credit=False,
        context=context(os.getpid()+1), libc_loaded=True,
        unshare={'return_code':0,'errno':0,'errno_name':'NONE'},
        netns_after='net:[4026532219]', interfaces=['lo'],
        ipv4=cap.ipv4(''), ipv6=cap.ipv6(route6()*2),
        connectivity={'connected':False,'exception':{'type':'gaierror','errno':-3}},
        exception=None, elapsed_seconds=0.002621)


def prerequisite():
    return dict(schema=pre.SCHEMA, stage='PREREQUISITE_PASS', qualified=True,
        acceptance_credit=False, parent_before=context(), parent_after=context(),
        child=child(), supervisor_exit=0, child_reaped=True, exception=None)
