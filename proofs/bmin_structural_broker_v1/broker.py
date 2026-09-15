"""One isolated invocation computes authority; recovery never calls send."""
from core import *
from journal import Journal


class Broker:
    def __init__(self, config, provider):
        # Freeze a private JSON copy; ordinary input only reaches submit(raw).
        self.c = validate_config(parse(canonical(config)))
        self.p = provider

    def _check(self):
        validate_config(self.c)
        self.p.check(self.c)

    def _state(self, old, p):
        parents, history = self.p.read_file(old, 'history.json')
        state, decision = evaluate(history, p)
        return history, state, decision

    def submit(self, raw):
        possible_send = False
        try:
            p = proposal(raw)
            self._check()
            journal = Journal(self.p, self.c)
            if journal.stage != 'GENESIS':
                # Even an independently valid *different* proposal cannot open a
                # second lifecycle in this one-operation proof namespace.
                if journal.intent == p and journal.stage == 'TERMINAL':
                    observed = self.p.ref(AUTHORITY)
                    terminal = journal.records[-1][1]
                    require(observed == terminal['observed_authority'])
                    return dict(result=journal.result, replay=True, authority_send=False)
                return dict(result='BLOCKED_SPENT_OR_PENDING', authority_send=False)
            old = self.p.ref(AUTHORITY)
            require(old == self.c['initial_authority_sha'], 'STALE')
            history, state, decision = self._state(old, p)
            if decision['decision'] != 'ALLOW':
                return dict(result='REJECT', authority_send=False)
            authorization, plan = authorize(self.c, p, old, history)
            self.p.create(plan)
            journal.prepare(p, authorization)
            # All checks are repeated inside the same serialized broker after
            # candidate construction and durable preparation, before arming.
            try:
                self._check()
                require(self.p.ref(AUTHORITY) == old, 'STALE')
                now_history, now_state, now_decision = self._state(old, p)
                require(now_history == history and now_state == state and now_decision == decision)
                exact, exact_plan = authorize(self.c, p, old, now_history)
                require(exact == authorization and exact_plan == plan)
                fresh = Journal(self.p, self.c)
                require(fresh.head == journal.head and fresh.stage == 'PREPARED')
            except Exception:
                # This invocation has not armed or sent. Safe NO_SEND, if the
                # unchanged PREPARED chain can still be durably completed.
                journal.finish('NO_SEND', self.p.ref(AUTHORITY))
                return dict(result='NO_SEND', authority_send=False)
            journal.arm()
            # Arm persistence can take time. Recheck *after* it too. Any failure
            # here deliberately leaves SEND_ARMED, even if no transport began.
            self._check()
            require(self.p.ref(AUTHORITY) == old)
            require(self.p.ref(JOURNAL) == journal.head)
            require(self._state(old, p) == (history, state, decision))
            possible_send = True
            # The only call site. Provider also consumes its in-process latch
            # before touching the socket. No exception path calls this again.
            result = self.p.send_authority(plan, authorization, journal.head)
            if result != {'result': 'INDETERMINATE'}:
                return dict(result='BLOCKED_UNEXPECTED_PROVIDER_RESULT', authority_send=True)
            return dict(result='INDETERMINATE', authority_send=True,
                        operation_id=authorization['operation_id'], journal_head=journal.head)
        except Exception:
            return dict(result='INDETERMINATE' if possible_send else 'BLOCKED',
                        authority_send=possible_send)

    def reconcile(self):
        """New process, same durable ancestry; read authority, only append terminal."""
        try:
            self._check()
            journal = Journal(self.p, self.c)
            observed = self.p.ref(AUTHORITY)
            if journal.stage == 'GENESIS':
                require(observed == self.c['initial_authority_sha'])
                return dict(result='UNUSED', authority_send=False)
            a = journal.auth
            if journal.stage == 'TERMINAL':
                require(observed == journal.records[-1][1]['observed_authority'])
                return dict(result=journal.result, authority_send=False)
            if journal.stage == 'PREPARED':
                # Proven no SEND_ARMED in protected complete ancestry: no send
                # permit was ever released. Consume this abandoned operation.
                require(observed == a['expected_old_sha'])
                journal.finish('NO_SEND', observed)
                return dict(result='NO_SEND', authority_send=False)
            if observed == a['candidate_sha']:
                journal.finish('COMMITTED', observed)
                return dict(result='COMMITTED', authority_send=False)
            # Includes old SHA: absence of observed advancement is not proof of
            # definitive rejection or request quiescence. No timeout inference.
            return dict(result='BLOCKED_UNRESOLVED' if observed == a['expected_old_sha']
                        else 'BLOCKED_CONFLICT', authority_send=False)
        except Exception:
            return dict(result='BLOCKED', authority_send=False)
