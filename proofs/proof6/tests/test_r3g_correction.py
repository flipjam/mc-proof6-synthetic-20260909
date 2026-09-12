"""Only qualified-netns and route-lexical defect classes; all execution inert."""
import copy
import json
import socket
import unittest
from unittest.mock import Mock, patch
import test_r3g as prior
import d04_fixtures as f
cap, pre = f.cap, f.pre
CONTROLS = [chr(n) for n in (*range(9),11,12,*range(14,32),127)]


class QualifiedNamespace(unittest.TestCase):
    def rejects_every_boundary(self, record):
        with self.assertRaises((ValueError,TypeError,KeyError)):
            cap.validate_record(copy.deepcopy(record))
        result,_,_=prior.Prerequisite().exercise(child=copy.deepcopy(record))
        self.assertFalse(result['qualified'])
        receipt=f.prerequisite();receipt['child']=record
        with self.assertRaises((ValueError,TypeError,KeyError)):
            pre.setup_qualification(json.dumps(receipt))

    def test_null_after(self):
        record=f.child();record['netns_after']=None
        self.rejects_every_boundary(record)

    def test_null_before(self):
        record=f.child();record['context']['netns']=None
        self.rejects_every_boundary(record)

    def test_missing_namespace_or_context(self):
        for key in ('netns_after','netns','context'):
            record=f.child()
            if key=='netns':del record['context'][key]
            else:del record[key]
            with self.subTest(key=key):self.rejects_every_boundary(record)
        record=f.child();record['context']=None;self.rejects_every_boundary(record)

    def test_malformed_after(self):
        for value in ('','net:[]','net:[-1]','net:[123]\n','net:[123]x',
                      'net:['+'1'*21+']','net:[１２３]',12,[],{}):
            record=f.child();record['netns_after']=value
            with self.subTest(value=value):self.rejects_every_boundary(record)

    def test_malformed_before(self):
        for value in ('','other:[123]','net:[12\x1f3]',12):
            record=f.child();record['context']['netns']=value
            with self.subTest(value=value):self.rejects_every_boundary(record)

    def test_identical_namespaces(self):
        record=f.child();record['netns_after']=record['context']['netns']
        self.rejects_every_boundary(record)

    def test_valid_changed_namespaces(self):
        cap.validate_record(f.child())
        self.assertTrue(prior.Prerequisite().exercise()[0]['qualified'])
        self.assertTrue(pre.setup_qualification(json.dumps(f.prerequisite()))['qualified'])

    def test_partial_context_failure_retained(self):
        with patch.object(cap,'context',side_effect=OSError(2,'DO_NOT_LEAK')):
            record=cap.isolate()
        cap.validate_record(record)
        self.assertEqual(record['stage'],'CONTEXT_FAILED')
        self.assertIsNone(record['context']);self.assertIsNone(record['netns_after'])
        self.assertFalse(record['qualified']);self.assertNotIn('DO_NOT_LEAK',json.dumps(record))

    def test_partial_unshare_failure_retained(self):
        record,_,_=prior.Predicate().exercise(rc=-1,number=1)
        cap.validate_record(record)
        self.assertEqual(record['stage'],'UNSHARE_FAILED')
        self.assertIsNone(record['netns_after']);self.assertFalse(record['qualified'])
        result,_,_=prior.Prerequisite().exercise(child=record,rc=1)
        self.assertFalse(result['qualified']);self.assertEqual(result['child'],record)

    def test_real_prerequisite_integration_blocks_before_consumption(self):
        real_run=pre.run
        for field,value in [('netns_after',None),('netns',None),('netns_after','bad'),
                            ('netns_after',f.context()['netns'])]:
            record=f.child()
            if field=='netns':record['context'][field]=value
            else:record[field]=value
            proc=Mock(returncode=0)
            proc.__enter__=Mock(return_value=proc);proc.__exit__=Mock(return_value=None)
            proc.communicate.return_value=(json.dumps(record).encode(),None)
            def helper():
                with patch.object(cap,'context',return_value=f.context()), \
                     patch.object(pre.subprocess,'Popen',return_value=proc):
                    return real_run()
            case=prior.Admission();case.setUp();before=copy.deepcopy(case.g.refs)
            code,result,_,actual,generic=case.run_d04(prerequisite=helper)
            self.assertEqual(code,1);self.assertEqual(result['result'],'PRECONDITION_BLOCKED')
            self.assertEqual(case.g.refs,before)
            self.assertEqual((case.g.journal_sends,case.g.authority_sends),(0,0))
            self.assertFalse(any(call[1] in ('POST','PATCH','PUT','DELETE') for call in case.g.calls))
            actual.assert_not_called();generic.assert_not_called()


class RouteLexical(unittest.TestCase):
    def rejects(self, family, raw):
        parsed=getattr(cap,family)(raw)
        self.assertFalse(parsed['qualified']);self.assertFalse(parsed['valid'])
        # Public process qualification, not merely lexical helper tests.
        record,_,_=prior.Predicate().exercise(**{'v4' if family=='ipv4' else 'v6':raw})
        self.assertFalse(record['qualified'])
        self.assertEqual(record['stage'],family.upper()+'_ROUTES_FAILED')
        self.assertTrue(record[family]['read_success'])

    def test_ipv4_exact_reviewer_suffixes(self):
        for control in ('\x1e','\x1f'):
            self.rejects('ipv4',' '.join(cap.HEADER)+control)

    def test_ipv4_control_field_separators(self):
        for control in CONTROLS:
            with self.subTest(control=ord(control)):
                self.rejects('ipv4',control.join(cap.HEADER)+'\n')

    def test_ipv4_trailing_controls_and_control_only(self):
        for control in CONTROLS:
            with self.subTest(control=ord(control)):
                self.rejects('ipv4','\t'.join(cap.HEADER)+control+'\n')
                self.rejects('ipv4',control)

    def test_embedded_nul(self):
        self.rejects('ipv4',' '.join(cap.HEADER).replace('Destination','Dest\x00ination'))
        self.rejects('ipv6',f.route6().replace('lo','l\x00o'))

    def test_ipv6_control_field_separators(self):
        for control in CONTROLS:
            with self.subTest(control=ord(control)):
                self.rejects('ipv6',f.route6().replace(' ',control))

    def test_ipv6_trailing_controls(self):
        for control in CONTROLS:
            with self.subTest(control=ord(control)):
                self.rejects('ipv6',f.route6().rstrip('\n')+control+'\n')
                self.rejects('ipv6',f.route6()+control)

    def test_non_ascii_whitespace_rejected(self):
        for separator in ('\x85','\xa0','\u2003','\u2028','\u2029'):
            self.rejects('ipv4',separator.join(cap.HEADER))
            self.rejects('ipv6',f.route6().replace(' ',separator))

    def test_supported_whitespace_and_empty_observation(self):
        self.assertTrue(prior.Predicate().exercise()[0]['qualified'])
        for separator in (' ','\t',' \t '):
            for ending in ('','\n','\r\n'):
                v4=separator.join(cap.HEADER)+ending
                v6=f.route6().rstrip('\n').replace(' ',separator)+ending
                self.assertTrue(cap.ipv4(v4)['qualified'])
                self.assertTrue(cap.ipv6(v6)['qualified'])
                self.assertTrue(prior.Predicate().exercise(v4=v4,v6=v6)[0]['qualified'])

    def test_bare_cr_and_blank_lines_not_empty_tables(self):
        for family,valid in [('ipv4',' '.join(cap.HEADER)),('ipv6',f.route6().rstrip('\n'))]:
            for raw in (valid+'\r',valid+'\r\r\n',valid+'\n\n','\n','\r\n',' \t'):
                self.rejects(family,raw)

    def test_end_recheck_rejects_unsupported_route_controls(self):
        for family in ('ipv4','ipv6'):
            record=f.child()
            def read(path):
                if path.endswith('/route'):
                    return ' '.join(cap.HEADER)+'\x1f' if family=='ipv4' else ''
                return f.route6().replace(' ','\x1e')
            with patch.object(cap,'netns',return_value=record['netns_after']), \
                 patch.object(cap.socket,'if_nameindex',return_value=[(1,'lo')]), \
                 patch.object(cap,'read',side_effect=read),self.assertRaises(cap.CapabilityError):
                cap.recheck(record)
            self.assertFalse(record['qualified'])
            self.assertEqual(record['stage'],family.upper()+'_ROUTES_FAILED')
            cap.validate_record(record)


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
