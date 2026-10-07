from __future__ import annotations
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from dns_explicit import parse_response, fill_missing
from dns_wildcard import classify
from execution import BudgetExceeded

HOST = 'app.example.test'


def packet(host=HOST, rrtype='A', status='NOERROR', answer='', authority='example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 2 3 4 5'):
    return (f';; ->>HEADER<<- opcode: QUERY, status: {status}, id: 42\n'
            f';; flags: qr rd ra; QUERY: 1, ANSWER: {len(answer.splitlines())}, AUTHORITY: {len(authority.splitlines())}, ADDITIONAL: 1\n'
            f';; QUESTION SECTION:\n;{host}. IN {rrtype}\n'
            f';; ANSWER SECTION:\n{answer}\n;; AUTHORITY SECTION:\n{authority}\n'
            ';; SERVER: 8.8.8.8#53(8.8.8.8)\n')


class ExplicitDNS(unittest.TestCase):
    def test_explicit_nxdomain_and_nodata(self):
        for status in ('NXDOMAIN', 'NOERROR'):
            self.assertEqual(parse_response(packet(status=status), HOST, 'A'), ())

    def test_cname_chain_without_aaaa(self):
        text = packet(rrtype='AAAA', answer=f'{HOST}. 30 IN CNAME edge.cdn.test.',
                      authority='cdn.test. 300 IN SOA ns.cdn.test. hostmaster.cdn.test. 1 2 3 4 5')
        self.assertEqual(parse_response(text, HOST, 'AAAA'), ())

    def test_positive_and_immediate_cname(self):
        self.assertEqual(parse_response(packet(answer=f'{HOST}. 30 IN A 192.0.2.1'), HOST, 'A'), ('192.0.2.1',))
        self.assertEqual(parse_response(packet(rrtype='CNAME', answer=f'{HOST}. 30 IN CNAME edge.cdn.test.'), HOST, 'CNAME'), ('edge.cdn.test',))

    def test_fail_closed(self):
        base = packet()
        for text in ('', base.replace('NOERROR', 'SERVFAIL'), base.replace('NOERROR', 'REFUSED'),
                     base.replace('qr rd', 'qr tc rd'), base.replace('qr rd', 'rd'),
                     base.replace(';app.example.test. IN A', ';other.example.test. IN A'),
                     base.replace('8.8.8.8#53', '1.1.1.1#53'), base + base,
                     packet(authority=''), packet(authority='other.test. 30 IN SOA ns.other.test. admin.other.test. 1 2 3 4 5'),
                     packet(answer=f'{HOST}. 30 IN A garbage'),
                     packet(status='NXDOMAIN', answer=f'{HOST}. 30 IN A 192.0.2.1')):
            with self.subTest(text=text):
                self.assertIsNone(parse_response(text, HOST, 'A'))

    def test_controls_restore_non_wildcard_only_with_explicit_evidence(self):
        controls = ['random1.example.test', 'random2.example.test', 'random3.example.test']
        rounds = []
        for _ in range(2):
            evidence = {}
            for rrtype in ('A', 'AAAA', 'CNAME'):
                evidence[rrtype] = {c: parse_response(packet(c, rrtype, 'NXDOMAIN'), c, rrtype) for c in controls}
                answer = f'{HOST}. 30 IN A 192.0.2.1' if rrtype == 'A' else ''
                evidence[rrtype][HOST] = parse_response(packet(rrtype=rrtype, answer=answer), HOST, rrtype)
            rounds.append(evidence)
        self.assertEqual(classify(HOST, controls, rounds), ('non_wildcard', 'explicit_negative_controls'))
        del rounds[1]['AAAA'][controls[0]]
        self.assertEqual(classify(HOST, controls, rounds)[0], 'unknown')

    def context(self, directory, budget=None, timed_out=False, returncode=0):
        def run(args, **kwargs):
            Path(kwargs['output_path']).write_text(packet(status='NXDOMAIN'))
            return SimpleNamespace(returncode=returncode, timed_out=timed_out)
        return SimpleNamespace(policy=SimpleNamespace(
            host_in_scope=lambda h: h == HOST,
            limits=SimpleNamespace(max_dns_queries=100, dns_rate=100, timeout_seconds=1800), name='example.test'),
            budget=budget, next_requested=lambda: False,
            current=Path(directory), runner=SimpleNamespace(run=Mock(side_effect=run)),
            db=Mock(), run_id='test')

    def test_fallback_audits_and_charges_only_missing_hosts(self):
        with tempfile.TemporaryDirectory() as directory, patch('dns_explicit.tool_path', return_value='dig'):
            budget = Mock()
            ctx = self.context(directory, budget)
            values = {'already.example.test': ('192.0.2.1',)}
            outcomes, used = fill_missing(ctx, {HOST, *values}, 'A', values, 0, 0, {'used': 0, 'reserved': 24})
            self.assertEqual(used, 1)
            self.assertEqual(values[HOST], ())
            budget.consume.assert_called_once_with('dns_queries', 1)
            self.assertEqual(outcomes[0]['resolver'], '8.8.8.8')
            self.assertTrue((Path(directory) / outcomes[0]['raw_artifact']).is_file())
            args = ctx.runner.run.call_args.args[0]
            self.assertIn('-r', args)  # ignore user .digrc
            self.assertIn('+tries=1', args)
            self.assertIn('+ignore', args)  # no hidden TCP retry

    def test_budget_scope_cap_stop_and_missing_tool_do_not_send(self):
        with tempfile.TemporaryDirectory() as directory, patch('dns_explicit.tool_path', return_value='dig'):
            for mode in ('budget', 'scope', 'cap', 'stop', 'local_budget'):
                ctx = self.context(directory, Mock())
                state = {'used': 0, 'reserved': 24}
                if mode == 'budget': ctx.budget.consume.side_effect = BudgetExceeded('dns_queries', 101, 100)
                if mode == 'scope': ctx.policy.host_in_scope = lambda h: False
                if mode == 'cap': state['used'] = 128
                if mode == 'stop': ctx.next_requested = lambda: True
                if mode == 'local_budget': ctx.budget = None; state['reserved'] = 100
                values = {}
                self.assertEqual(fill_missing(ctx, {HOST}, 'A', values, 0, 0, state)[1], 0)
                ctx.runner.run.assert_not_called()
            with patch('dns_explicit.tool_path', return_value=None):
                ctx = self.context(directory)
                self.assertEqual(fill_missing(ctx, {HOST}, 'A', {}, 0, 0, {'used': 0, 'reserved': 0}), ([], 0))

    def test_timeout_or_nonzero_output_is_not_negative(self):
        with tempfile.TemporaryDirectory() as directory, patch('dns_explicit.tool_path', return_value='dig'):
            for timeout, code in ((True, 124), (False, 1)):
                values = {}
                ctx = self.context(directory, timed_out=timeout, returncode=code)
                outcomes, used = fill_missing(ctx, {HOST}, 'A', values, 0, 0, {'used': 0, 'reserved': 0})
                self.assertEqual(used, 1)
                self.assertEqual(values, {})
                self.assertEqual(outcomes[0]['stop_reason'], 'unknown')

if __name__ == '__main__': unittest.main()
