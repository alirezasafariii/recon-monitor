from __future__ import annotations
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import TargetPolicy
from dns_wildcard import classify, detect, observations
import test_dns_collection_quality as collection
from stages import stage_dns


def evidence(controls, host, a=('192.0.2.1',), cname=()):
    return [{t: {h: v for h in controls + [host]}
             for t, v in [('A', a), ('AAAA', ()), ('CNAME', cname)]} for _ in range(2)]


class WildcardDecisionTests(unittest.TestCase):
    def test_repeated_random_names_and_exact_rrsets_support_candidate(self):
        controls = ['a.test', 'b.test', 'c.test']
        self.assertEqual(classify('real.test', controls, evidence(controls, 'real.test'))[0], 'wildcard_candidate')

    def test_ip_overlap_alone_is_not_a_match(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test')
        for row in r:
            row['A']['real.test'] = ('192.0.2.1', '192.0.2.2')
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_distinct_cname_on_shared_ip_is_unknown(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test', cname=('cdn.test',))
        for row in r:
            row['CNAME']['real.test'] = ('real-cdn.test',)
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_known_cname_presence_difference_is_not_address_match(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test', cname=('cdn.test',))
        for row in r:
            row['CNAME']['real.test'] = ()
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_distinct_ipv6_profile_prevents_ipv4_only_classification(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test')
        for row in r:
            row['AAAA']['real.test'] = ('2001:db8::1',)
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_rotating_addresses_with_stable_cname_are_candidates(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test', cname=('cdn.test',))
        r[1]['A']['a.test'] = ('192.0.2.2',)
        self.assertEqual(classify('real.test', c, r)[0], 'wildcard_candidate')

    def test_rotating_addresses_without_cname_are_unknown(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test')
        r[1]['A']['a.test'] = ('192.0.2.2',)
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_only_complete_explicit_negatives_can_clear_flag(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test', a=())
        for row in r:
            row['A']['real.test'] = ('192.0.2.1',)
        self.assertEqual(classify('real.test', c, r)[0], 'non_wildcard')
        del r[0]['AAAA']['b.test']
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_no_candidate_observation_never_clears_flag(self):
        c = ['a.test', 'b.test', 'c.test']; r = evidence(c, 'real.test', a=())
        self.assertEqual(classify('real.test', c, r)[0], 'unknown')

    def test_invalid_warning_error_and_duplicate_conflict_are_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'answers'
            for rows in ['', '[WRN] resolve failed\n', json.dumps({'host': 'h.test', 'a': ['bad']})+'\n',
                         json.dumps({'host': 'h.test', 'status_code': 'SERVFAIL'})+'\n',
                         json.dumps({'host': 'h.test', 'a': ['192.0.2.1']})+'\n'+json.dumps({'host': 'h.test', 'status_code': 'NXDOMAIN'})+'\n']:
                p.write_text(rows)
                self.assertEqual(observations(p, {'h.test'}, 'A')[0], {})
            p.write_text(json.dumps({'host': 'h.test', 'status_code': 'NXDOMAIN'})+'\n')
            self.assertEqual(observations(p, {'h.test'}, 'A')[0], {'h.test': ()})


class WildcardIntegrationTests(unittest.TestCase):
    TARGET = collection.DNSCollectionQualityTests.TARGET
    FLAGS = collection.DNSCollectionQualityTests.FLAGS
    setUp = collection.DNSCollectionQualityTests.setUp
    _context = collection.DNSCollectionQualityTests._context
    def runner(self, mode='positive'):
        def run(args, **kwargs):
            rrtype = next(v for flag, v in self.FLAGS.items() if flag in args)
            hosts = Path(args[args.index('-l')+1]).read_text().splitlines()
            controls = '-retry' in args
            if controls:
                self.assertIn('-rcode', args)
                self.assertEqual(args[args.index('-retry')+1], '1')
                self.assertTrue(all(self.policy.host_in_scope(h) for h in hosts))
            rows = []
            for h in hosts:
                vals = ['192.0.2.20'] if rrtype == 'A' else []
                status = 'NOERROR'
                if controls and mode == 'negative' and h.startswith('recon-wc-'):
                    vals = []; status = 'NXDOMAIN'
                rows.append({'host': h, rrtype.lower(): vals, 'status_code': status})
            out = '\n'.join(json.dumps(r) for r in rows)+'\n'
            if controls and mode == 'warning':
                out = '[WRN] all domains failed to resolve\n'
            Path(kwargs['output_path']).write_text(out)
            return SimpleNamespace(returncode=124 if controls and mode == 'timeout' else 0,
                                   timed_out=controls and mode == 'timeout', duration=.1, lines=len(rows))
        return run

    def detect_stage(self, mode):
        host = 'app.' + self.TARGET
        (self.current / 'subdomains.txt').write_text(host+'\n')
        self.db.upsert_asset(self.TARGET, host, ['fixture'], 'previous', wildcard=True)
        self.db.upsert_dns(self.TARGET, host, 'A', '192.0.2.10', 'previous')
        from dns_wildcard import detect
        with patch('stages.tool_path', return_value='dnsx'), patch('stages.detect_dns_wildcards', side_effect=detect):
            metrics = stage_dns(self._context(self.runner(mode)))
        return host, metrics

    def test_positive_controls_classify_without_excluding_or_polluting(self):
        host, metrics = self.detect_stage('positive')
        self.assertEqual(metrics['wildcard_candidates'], 1)
        self.assertEqual(metrics['wildcard_probe_queries'], 24)
        self.assertTrue(metrics['wildcard_classification_complete'])
        self.assertEqual((self.current / 'resolved-hosts.txt').read_text().splitlines(), [host])
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM assets')[0], 1)
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM dns_records WHERE is_current=1 AND host LIKE ?', ('recon-wc-%',))[0], 0)
        audit = json.loads((self.current / 'dns-wildcard-evidence.jsonl').read_text())
        self.assertEqual(len(audit['controls']), 3)
        self.assertEqual(len(audit['observations']), 2)
        self.assertEqual(audit['state'], 'wildcard_candidate')

    def test_explicit_negative_controls_clear_previous_flag(self):
        host, metrics = self.detect_stage('negative')
        self.assertTrue(metrics['wildcard_classification_complete'])
        self.assertEqual(self.db.one('SELECT wildcard FROM assets WHERE host=?', (host,))[0], 0)
        self.assertEqual(metrics['wildcard_candidates'], 0)

    def test_warnings_and_timeout_preserve_flags_and_dns(self):
        for mode in ('warning', 'timeout'):
            host, metrics = self.detect_stage(mode)
            self.assertFalse(metrics['wildcard_classification_complete'])
            self.assertTrue(metrics['dns_collection_complete'])
            self.assertEqual(metrics['collection_status'], 'completed')
            self.assertTrue(metrics['wildcard_coverage_reasons'])
            self.assertEqual(self.db.one('SELECT wildcard FROM assets WHERE host=?', (host,))[0], 1)
            self.assertEqual(metrics['wildcard_unknown_hosts'], 1)
            self.assertEqual((self.current / 'resolved-hosts.txt').read_text().splitlines(), [host])

    def test_excluded_random_names_do_not_get_queried(self):
        self.policy.exclude.append('recon-wc-')
        host, metrics = self.detect_stage('positive')
        self.assertFalse(metrics['wildcard_classification_complete'])
        self.assertEqual(metrics['wildcard_probe_queries'], 0)
        self.assertEqual(metrics['collection_status'], 'completed')
        self.assertEqual(metrics['wildcard_coverage_reasons'], ['control_scope_or_collision'])
        self.assertEqual(self.db.one('SELECT wildcard FROM assets WHERE host=?', (host,))[0], 1)

    def test_budget_exhaustion_prevents_control_queries(self):
        self.policy.limits.max_dns_queries = 10
        host, metrics = self.detect_stage('positive')
        self.assertEqual(metrics['wildcard_probe_queries'], 0)
        self.assertFalse(metrics['wildcard_classification_complete'])
        self.assertTrue(metrics['dns_collection_complete'])
        self.assertEqual(metrics['wildcard_coverage_reasons'], ['probe_budget'])


    def test_real_detector_100_host_warning_only_preserves_all_state(self):
        hosts = [self.TARGET] + [f"h{i}.{self.TARGET}" for i in range(99)]
        (self.current / 'subdomains.txt').write_text('\n'.join(hosts))
        for host in hosts:
            self.db.upsert_asset(self.TARGET, host, ['fixture'], 'previous', wildcard=True, resolved=True)
            self.db.upsert_dns(self.TARGET, host, 'A', '192.0.2.10', 'previous')
        def runner(args, **kwargs):
            Path(kwargs['output_path']).write_text('[WRN] 100 domains failed to resolve\n')
            return SimpleNamespace(returncode=0, timed_out=False, duration=.1, lines=1)
        from dns_wildcard import detect
        with patch('stages.tool_path', return_value='dnsx'), patch('stages.detect_dns_wildcards', side_effect=detect):
            metrics = stage_dns(self._context(runner))
        self.assertEqual(metrics['removed_records'], 0)
        self.assertFalse(metrics['dns_collection_complete'])
        self.assertEqual(metrics['collection_status'], 'partial')
        self.assertIn('dns_zero_observation', metrics['collection_reasons'])
        self.assertEqual(metrics['effective_resolved_hosts'], 100)
        self.assertEqual(metrics['wildcard_candidates'], 0)
        self.assertFalse(metrics['wildcard_classification_complete'])
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM assets WHERE wildcard=1 AND resolved=1')[0], 100)
        self.assertEqual(set((self.current / 'resolved-hosts.txt').read_text().splitlines()), set(hosts))

    def test_dnsx_omissions_use_explicit_controls_without_changing_primary_state(self):
        from test_dns_explicit import packet
        host = 'app.' + self.TARGET
        (self.current / 'subdomains.txt').write_text(host+'\n')
        self.db.upsert_asset(self.TARGET, host, ['fixture'], 'previous', wildcard=True)
        ordinary = self.runner()
        def run(args, **kwargs):
            if args[0] == 'dig':
                name, rrtype = args[3:5]
                status = 'NXDOMAIN' if name.startswith('recon-wc-') else 'NOERROR'
                answer = f'{name}. 30 IN A 192.0.2.20' if status == 'NOERROR' and rrtype == 'A' else ''
                Path(kwargs['output_path']).write_text(packet(name, rrtype, status, answer))
                return SimpleNamespace(returncode=0, timed_out=False)
            if '-retry' in args:
                rrtype = next(v for flag, v in self.FLAGS.items() if flag in args)
                rows = [{'host': host, 'a': ['192.0.2.20'], 'status_code': 'NOERROR'}] if rrtype == 'A' else []
                Path(kwargs['output_path']).write_text(''.join(json.dumps(r)+'\n' for r in rows))
                return SimpleNamespace(returncode=0, timed_out=False, duration=.1)
            return ordinary(args, **kwargs)
        with patch('dns_explicit.tool_path', return_value='dig'), patch('stages.tool_path', return_value='dnsx'), patch('stages.detect_dns_wildcards', side_effect=detect):
            metrics = stage_dns(self._context(run))
        self.assertTrue(metrics['dns_collection_complete'])
        self.assertTrue(metrics['wildcard_classification_complete'])
        self.assertEqual(metrics['wildcard_candidates'], 0)
        self.assertEqual(self.db.one('SELECT wildcard FROM assets WHERE target=? AND host=?', (self.TARGET, host))[0], 0)
        self.assertEqual(metrics['effective_resolved_hosts'], 1)
        self.assertEqual(metrics['wildcard_probe_queries'], 46)  # 24 dnsx + 22 explicit omissions
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM assets')[0], 1)

    def test_real_budget_reservation_and_runtime_failure(self):
        from execution import BudgetExceeded
        ctx = self._context(self.runner())
        class Budget:
            def __init__(self): self.used = 0
            def snapshot(self): return {'dns_queries': {'limit': 100, 'used': self.used}}
            def consume(self, metric, amount): self.used += amount
            def check_runtime(self): raise BudgetExceeded('runtime_seconds', 100, 10)
        ctx.budget = Budget()
        rows, outcomes, reserved = detect(ctx, ['app.'+self.TARGET])
        self.assertEqual(ctx.budget.used, 24)
        self.assertEqual(reserved, 24)
        self.assertEqual(rows[0]['state'], 'unknown')
        self.assertTrue(all(r['stop_reason']=='runtime_budget' for r in outcomes))

    def test_parent_limit_keeps_unprobed_state_unknown(self):
        ctx = self._context(self.runner())
        with patch('dns_wildcard.MAX_PARENTS', 0):
            rows, outcomes, reserved = detect(ctx, ['app.'+self.TARGET])
        self.assertEqual(rows[0]['reason'], 'probe_limit')
        self.assertEqual(outcomes, [])
        self.assertEqual(reserved, 0)

    def test_budget_remaining_check_does_not_overconsume(self):
        from unittest.mock import Mock
        ctx = self._context(self.runner())
        ctx.budget = Mock()
        ctx.budget.snapshot.return_value = {'dns_queries': {'limit': 100, 'used': 90}}
        rows, outcomes, reserved = detect(ctx, ['app.'+self.TARGET])
        ctx.budget.consume.assert_not_called()
        self.assertEqual(rows[0]['reason'], 'probe_budget')
        self.assertEqual(reserved, 0)


    def test_129_siblings_preserve_flags_and_complete_primary_collection(self):
        hosts = [f'h{i}.{self.TARGET}' for i in range(129)]
        (self.current / 'subdomains.txt').write_text('\n'.join(hosts))
        for host in hosts:
            self.db.upsert_asset(self.TARGET, host, ['fixture'], 'previous', wildcard=True)
        with patch('stages.tool_path', return_value='dnsx'), patch('stages.detect_dns_wildcards', side_effect=detect):
            metrics = stage_dns(self._context(self.runner()))
        self.assertEqual(metrics['collection_status'], 'completed')
        self.assertTrue(metrics['dns_collection_complete'])
        self.assertEqual(metrics['collection_reasons'], [])
        self.assertFalse(metrics['wildcard_classification_complete'])
        self.assertEqual(metrics['wildcard_coverage_reasons'], ['probe_limit'])
        self.assertEqual(metrics['wildcard_unknown_hosts'], 129)
        self.assertEqual(metrics['wildcard_probe_queries'], 0)
        self.assertEqual(metrics['effective_resolved_hosts'], 129)
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM assets WHERE wildcard=1')[0], 129)

    def test_seventeenth_parent_is_a_visible_gap_not_partial_dns(self):
        hosts = [f'app.p{i:02d}.{self.TARGET}' for i in range(17)]
        (self.current / 'subdomains.txt').write_text('\n'.join(hosts))
        with patch('stages.tool_path', return_value='dnsx'), patch('stages.detect_dns_wildcards', side_effect=detect):
            metrics = stage_dns(self._context(self.runner()))
        self.assertEqual(metrics['collection_status'], 'completed')
        self.assertTrue(metrics['dns_collection_complete'])
        self.assertFalse(metrics['wildcard_classification_complete'])
        self.assertEqual(metrics['wildcard_unknown_hosts'], 1)
        self.assertEqual(metrics['wildcard_candidates'], 16)
        self.assertEqual(metrics['effective_resolved_hosts'], 17)
        self.assertEqual(metrics['wildcard_coverage_reasons'], ['probe_limit'])

    def test_healthy_dns_with_wildcard_gaps_persists_successful_baseline(self):
        import contextlib, io
        from core import AppPaths, Config, Logger, PolicySet
        import recon_monitor_core as runtime
        from reporting import _stage_metrics
        for mode, count in [('positive',129), ('warning',1)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
                paths = AppPaths.from_root(Path(temp)); paths.ensure()
                paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
                db = runtime.Database(paths.db); stack.callback(db.close)
                orchestrator = runtime.Orchestrator(paths, Config(paths), Logger(paths), db,
                                                    progress=False, allow_active=False)
                hosts = [f'h{i}.{self.TARGET}' for i in range(count)]
                def offline_stage(ctx):
                    (ctx.current / 'subdomains.txt').write_text('\n'.join(hosts))
                    return {'collection_status':'completed'}
                captured = {}
                def report(ctx, baseline):
                    captured.update(_stage_metrics(ctx))
                    return {'analysis':{'analysis_id':'offline'}, 'finding_notifications':{'status':'success'}}
                stages = {name:offline_stage for name in runtime.STAGE_FUNCTIONS}
                stages['dns'] = stage_dns
                stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
                stack.enter_context(patch('recon_monitor_core.stage_report', side_effect=report))
                stack.enter_context(patch.object(orchestrator, '_record_versions'))
                stack.enter_context(patch.object(orchestrator, 'install_signal_handlers'))
                stack.enter_context(patch.object(orchestrator.runner, 'run', side_effect=self.runner(mode)))
                stack.enter_context(patch('stages.tool_path', return_value='dnsx'))
                stack.enter_context(patch('stages.detect_dns_wildcards', side_effect=detect))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(orchestrator.run(PolicySet({}, [self.policy], paths.policy)), 0)
                run = orchestrator.current_run_id
                self.assertEqual(db.stage_status(run,self.TARGET,'dns'), 'success')
                lifecycle = db.one('SELECT * FROM target_run_lifecycle WHERE run_id=?',(run,))
                self.assertTrue(lifecycle['baseline_eligible'])
                self.assertEqual(lifecycle['collection_status'], 'success')
                self.assertEqual(db.successful_snapshot_status(self.TARGET)['run_id'], run)
                self.assertEqual(captured['dns']['status'], 'success')
                self.assertFalse(captured['dns']['metrics']['wildcard_classification_complete'])
                self.assertTrue(captured['dns']['metrics']['dns_collection_complete'])
                self.assertTrue(captured['dns']['metrics']['wildcard_coverage_reasons'])
