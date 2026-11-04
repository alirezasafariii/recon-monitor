"""Collection must use spare permitted capacity without inventing coverage."""
from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_dns_collection_quality as dns_fixture
import test_katana_execution_quality as katana_fixture
from core import TargetPolicy
from execution import BudgetExceeded, BudgetManager
from dns_explicit import fill_missing_round_robin
from katana_completion import CONTRACT
from stages import stage_dns, stage_urls
from test_dns_explicit import packet


class DNSBudgetProgressTests(unittest.TestCase):
    def fixture(self, host_count=166, dns_limit=5000):
        f = dns_fixture.DNSCollectionQualityTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.policy = TargetPolicy.from_dict({
            'name': f.TARGET, 'roots': [f.TARGET],
            'analysis': {'asset_graph': False},
            'limits': {'max_dns_queries': dns_limit, 'timeout_seconds': 900},
        })
        ctx = f._context(None)
        hosts = [f'h{i:03}.example.test' for i in range(host_count)]
        (ctx.current / 'subdomains.txt').write_text('\n'.join(hosts) + '\n')
        ctx.budget = BudgetManager.create(ctx.db, ctx.run_id, ctx.policy.name, ctx.policy)
        calls = []

        def run(args, **kwargs):
            out = Path(kwargs['output_path'])
            if args[0] == '/usr/bin/dig':
                host, rrtype = args[2:4]
                calls.append((host, rrtype))
                out.write_text(packet(host, rrtype))
            else:
                out.write_text('')  # real dnsx can omit every negative answer
            return SimpleNamespace(returncode=0, timed_out=False, operator_next=False,
                                   duration=.1, lines=len(out.read_text().splitlines()))

        ctx.runner = SimpleNamespace(run=run)
        return ctx, calls, hosts

    def tools(self):
        return patch.multiple('stages', tool_path=lambda _: 'dnsx')

    def test_166_hosts_complete_all_rrsets_in_one_attempt_and_reuse_proof(self):
        ctx, calls, hosts = self.fixture()
        with self.tools(), patch('dns_explicit.tool_path', return_value='/usr/bin/dig'), \
                patch('dns_explicit.time.sleep'):
            first = stage_dns(ctx)
            resumed = stage_dns(ctx)
        self.assertEqual(first['collection_status'], 'completed')
        self.assertEqual(first['observed_pairs'], 3 * len(hosts) + 1)
        self.assertEqual(first['unobserved_pairs'], 0)
        self.assertEqual(first['dns_explicit_queries'], 499)
        self.assertEqual(len(calls), 499)
        self.assertEqual(len(set(calls)), len(calls))
        self.assertEqual(resumed['dns_explicit_queries'], 0)
        self.assertEqual(resumed['dns_explicit_reused_queries'], 499)
        self.assertEqual(resumed['collection_status'], 'completed')
        self.assertLessEqual(ctx.budget.snapshot()['dns_queries']['used'], 5000)

    def test_limited_budget_reaches_later_rrtypes_and_preserves_unknown_records(self):
        ctx, calls, hosts = self.fixture(host_count=23, dns_limit=100)
        ctx.db.upsert_dns(ctx.policy.name, hosts[-1], 'CNAME', 'old.example.test', 'old')
        with self.tools(), patch('dns_explicit.tool_path', return_value='/usr/bin/dig'), \
                patch('dns_explicit.time.sleep'):
            result = stage_dns(ctx)
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual({rrtype for _, rrtype in calls}, {'A', 'AAAA', 'CNAME', 'NS'})
        self.assertEqual(ctx.budget.snapshot()['dns_queries']['used'], 100)
        self.assertEqual(result['dns_explicit_stop_reason'], 'query_budget')
        self.assertEqual(result['unobserved_pairs'], 62)
        pending = [json.loads(line) for line in
                   (ctx.current / 'dns-unobserved-rrsets.jsonl').read_text().splitlines()]
        self.assertEqual(len(pending), 62)
        self.assertIsNotNone(ctx.db.one(
            "SELECT 1 FROM dns_records WHERE host=? AND rrtype='CNAME' AND is_current=1",
            (hosts[-1],),
        ))

    def test_shared_fallback_deadline_bounds_queries_and_keeps_unobserved_rrsets(self):
        ctx, calls, _ = self.fixture(host_count=23)
        ctx.policy.limits.timeout_seconds = 30
        clock = [0.0]
        runner = ctx.runner.run
        deadlines = []

        def slow(args, **kwargs):
            result = runner(args, **kwargs)
            if args[0] == '/usr/bin/dig':
                deadlines.append(clock[0] + kwargs['timeout'])
                clock[0] += 5
            return result

        ctx.runner.run = slow
        with self.tools(), patch('dns_explicit.tool_path', return_value='/usr/bin/dig'), \
                patch('dns_explicit.time.sleep'), \
                patch('dns_explicit.time.monotonic', side_effect=lambda: clock[0]):
            result = stage_dns(ctx)
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(value <= 30 for value in deadlines))
        self.assertEqual({rrtype for _, rrtype in calls}, {'A', 'AAAA', 'CNAME', 'NS'})
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(result['dns_explicit_stop_reason'], 'deadline')
        self.assertIn('dns_explicit_deadline', result['collection_reasons'])

    def test_blocked_fallback_still_verifies_cached_proof_without_new_requests(self):
        ctx, calls, hosts = self.fixture(host_count=2)
        with self.tools(), patch('dns_explicit.tool_path', return_value='/usr/bin/dig'), \
                patch('dns_explicit.time.sleep'):
            stage_dns(ctx)
            before = len(calls)
            values = {rrtype: {} for rrtype in ('A', 'AAAA', 'CNAME', 'NS')}
            state = {'used': 0, 'reserved': 0, 'blocked': True}
            outcomes = fill_missing_round_robin(ctx, [
                (rrtype, set(ctx.policy.roots if rrtype == 'NS' else hosts), values[rrtype], i)
                for i, rrtype in enumerate(values)
            ], state)
        self.assertEqual(len(calls), before)
        self.assertEqual(sum(len(rows) for rows in outcomes.values()), 7)
        self.assertTrue(all(row['reused'] for rows in outcomes.values() for row in rows))


class KatanaBudgetProgressTests(unittest.TestCase):
    setUp = katana_fixture.KatanaExecutionQualityTests.setUp
    _context = katana_fixture.KatanaExecutionQualityTests._context

    def exercise(self, *, mode='progress', request_limit=10000, deadline=900, resume_pending=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        clock = [0.0]
        origins = [f'https://h{i:03}.example.test' for i in range(88)]
        remaining = {origin: (100 if i >= 84 else 1) for i, origin in enumerate(origins)}
        seen, calls = Counter(), []
        budget_used = [0]

        def consume(metric, amount):
            self.assertEqual(metric, 'http_requests')
            if budget_used[0] + amount > request_limit:
                raise BudgetExceeded(metric, budget_used[0] + amount, request_limit)
            budget_used[0] += amount

        def run(args, **kwargs):
            batch = Path(args[args.index('-list') + 1]).read_text().splitlines()
            self.assertEqual(len(batch), 1)
            origin = batch[0]
            calls.append((origin, kwargs['timeout']))
            seen[origin] += 1
            seconds = int(args[args.index('-ct') + 1][:-1])
            attempted = min(remaining[origin], max(1, seconds))
            if mode == 'stalled' and origin == origins[-1]:
                attempted = 0
            slow_first = (origin == origins[-1] and (
                (mode == 'slow_root' and seen[origin] == 1) or mode == 'deadline_errors'))
            if slow_first:
                attempted = 0
            remaining[origin] -= attempted
            clock[0] += max(.1, attempted)
            reason = 'deadline' if remaining[origin] else 'queue_exhausted'
            row = dict(contract=CONTRACT, origin=origin, stop_reason=reason,
                       attempted_requests=attempted, failed_requests=0,
                       limited_requests=0, pending_items=remaining[origin], active_items=0)
            if slow_first:
                row.update(attempted_requests=1, failed_requests=1)
            if mode == 'request_error' and origin == origins[-1]:
                row.update(stop_reason='request_errors', failed_requests=attempted)
            text = 'invalid' if mode == 'malformed' and origin == origins[-1] else json.dumps(row)
            Path(args[args.index('-recon-completion-log') + 1]).write_text(text + '\n')
            if mode == 'throttle' and origin == origins[-1]:
                Path(args[args.index('-elog') + 1]).write_text(json.dumps({
                    'endpoint': origin + '/', 'error': 'HTTP 429; throttled',
                }) + '\n')
            Path(kwargs['output_path']).write_text(origin + f'/evidence-{seen[origin]}.js\n')
            stopped = mode == 'operator_next' and origin == origins[-4] and seen[origin] == 2
            if mode == 'deadline' and origin == origins[-4] and seen[origin] == 2:
                clock[0] = deadline + 1
            timed_out = mode == 'timeout' and origin == origins[-1]
            return SimpleNamespace(returncode=124 if timed_out else 0, timed_out=timed_out, operator_next=stopped,
                                   duration=max(.1, attempted), lines=1)

        ctx = self._context(Path(tmp.name), SimpleNamespace(run=run))
        ctx.policy = TargetPolicy.from_dict({
            'name': 'example.test', 'roots': ['example.test'],
            'analysis': {'asset_graph': False},
            'limits': {'timeout_seconds': deadline, 'request_rate': 3,
                       'max_http_requests': request_limit},
        })
        ctx.budget = SimpleNamespace(
            snapshot=lambda: {'http_requests': {'used': budget_used[0], 'limit': request_limit}},
            consume=consume,
        )
        with patch('stages.tool_path', side_effect=lambda name: name == 'katana'), \
                patch('stages._probe_live_origins', return_value=(origins, [])), \
                patch('stages._katana_completion_supported', return_value=True), \
                patch('stages._katana_checkpoint_supported', return_value=True), \
                patch('stages.time.monotonic', side_effect=lambda: clock[0]):
            result = stage_urls(ctx)
            if resume_pending:
                before = len(calls)
                resumed = stage_urls(ctx)
                self.assertEqual(resumed['collection_status'], 'partial')
                self.assertEqual(len(calls), before + 1)
                self.assertEqual(calls[-1][0], origins[-1])
        return ctx, result, calls, remaining, clock[0], budget_used[0]

    def test_busy_frontiers_finish_using_spare_time_after_every_origin_gets_a_turn(self):
        ctx, result, calls, remaining, duration, charged = self.exercise()
        self.assertEqual(result['collection_status'], 'completed')
        self.assertEqual(result['katana_pending_origins'], 0)
        self.assertTrue(all(value == 0 for value in remaining.values()))
        self.assertEqual(len({origin for origin, _ in calls[:88]}), 88)
        self.assertTrue(any(timeout > 32 for _, timeout in calls[88:]))
        self.assertLess(duration, 900)
        self.assertLessEqual(charged, result['katana_request_envelope'])
        self.assertEqual(charged, result['katana_reserved_requests'])
        self.assertGreater(result['katana_batches_incomplete_historical'], 0)
        self.assertEqual(result['katana_unique_origins_attempted_this_attempt'], 88)
        self.assertEqual(result['katana_continuation_batches_this_attempt'], 4)
        self.assertEqual((ctx.current / 'katana-pending-origins.txt').read_text(), '')
        # Continuation appends evidence from the first slice.
        self.assertIn('/evidence-1.js', (ctx.current / 'katana-urls.txt').read_text())
        self.assertIn('/evidence-2.js', (ctx.current / 'katana-urls.txt').read_text())

    def test_no_progress_does_not_spin_or_claim_complete(self):
        _, result, calls, _, _, _ = self.exercise(mode='stalled')
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(sum(origin.endswith('h087.example.test') for origin, _ in calls), 1)
        self.assertEqual(result['katana_pending_origins'], 1)

    def test_resume_skips_all_finished_origins_after_automatic_continuations(self):
        self.exercise(mode='stalled', resume_pending=True)

    def test_short_first_deadline_does_not_permanently_starve_a_slow_root(self):
        _, result, calls, _, _, _ = self.exercise(mode='slow_root')
        self.assertEqual(result['collection_status'], 'completed')
        self.assertEqual(sum(origin.endswith('h087.example.test') for origin, _ in calls), 2)

    def test_longer_turn_without_success_does_not_repeat_indefinitely(self):
        _, result, calls, _, _, _ = self.exercise(mode='deadline_errors')
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(sum(origin.endswith('h087.example.test') for origin, _ in calls), 2)
        self.assertEqual(result['katana_pending_origins'], 1)

    def test_tight_quota_leaves_backlog_without_overspending(self):
        _, result, _, _, _, charged = self.exercise(request_limit=200)
        self.assertEqual(result['collection_status'], 'partial')
        self.assertGreater(result['katana_pending_origins'], 0)
        self.assertLessEqual(charged, 200)

    def test_unverified_errors_and_throttled_origins_are_not_automatically_retried(self):
        for mode in ('request_error', 'malformed', 'timeout', 'throttle'):
            with self.subTest(mode=mode):
                _, result, calls, _, _, _ = self.exercise(mode=mode)
                self.assertEqual(result['collection_status'], 'partial')
                self.assertEqual(sum(origin.endswith('h087.example.test') for origin, _ in calls), 1)
                self.assertEqual(result['katana_pending_origins'], 1)
                if mode == 'throttle':
                    self.assertEqual(result['katana_request_error_categories_this_attempt']['http_429'], 1)

    def test_operator_next_stops_during_continuation_without_erasing_backlog(self):
        ctx, result, calls, _, _, charged = self.exercise(mode='operator_next')
        self.assertEqual(len(calls), 89)
        self.assertEqual(result['katana_stop_reason'], 'operator_next')
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(result['katana_pending_origins'], 4)
        self.assertEqual(len((ctx.current / 'katana-pending-origins.txt').read_text().splitlines()), 4)
        self.assertLessEqual(charged, result['katana_request_envelope'])

    def test_global_deadline_stops_continuations_and_retains_pending_work(self):
        _, result, calls, _, _, charged = self.exercise(mode='deadline')
        self.assertEqual(len(calls), 89)
        self.assertTrue(result['katana_deadline_exhausted'])
        self.assertEqual(result['katana_stop_reason'], 'global_deadline')
        self.assertEqual(result['collection_status'], 'partial')
        self.assertEqual(result['katana_pending_origins'], 3)
        self.assertLessEqual(charged, result['katana_request_envelope'])


if __name__ == '__main__':
    unittest.main()
