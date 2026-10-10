"""Offline integration: explicit completion controls per-origin stage backlog."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import test_katana_execution_quality as quality
from katana_completion import CONTRACT
from stages import stage_urls, _katana_completion_supported, _katana_checkpoint_supported


class KatanaStageCompletionTests(unittest.TestCase):
    setUp = quality.KatanaExecutionQualityTests.setUp
    _context = quality.KatanaExecutionQualityTests._context

    def exercise(self, mode, *, supported=True, returncode=0, timed_out=False, operator_next=False, resume=False, origin_count=2, resume_remaining=None, failed_index=1, checkpoint=False):
        with tempfile.TemporaryDirectory() as tmp:
            origins = ['https://a.example.test', 'https://b.example.test']
            origins += [f'https://h{i}.example.test' for i in range(origin_count - 2)]
            self.last_crawl_limits = []
            self.last_input_batches = []
            self.checkpoint_paths = []
            def runner(args, **kwargs):
                batch_origins = Path(args[args.index('-list')+1]).read_text().splitlines()
                self.last_input_batches.append(batch_origins)
                if checkpoint:
                    self.assertEqual(len(batch_origins), 1)
                    frontier = Path(args[args.index('-recon-checkpoint-dir')+1])
                    self.checkpoint_paths.append(str(frontier))
                    self.assertEqual(frontier.stat().st_mode & 0o777, 0o700)
                    sentinel = frontier / 'sentinel'
                    if sentinel.exists():
                        self.assertEqual(sentinel.read_text(), 'prior frontier preserved')
                    sentinel.write_text('prior frontier preserved')
                else:
                    self.assertNotIn('-recon-checkpoint-dir', args)
                self.last_crawl_limits.append(int(args[args.index("-ct")+1][:-1]))
                Path(kwargs['output_path']).write_text(origins[0]+'/evidence.js\n')
                if supported:
                    path = Path(args[args.index('-recon-completion-log')+1])
                    self.assertEqual(path.read_text(), '')
                    rows = []
                    for i, origin in enumerate(batch_origins):
                        if mode == 'missing' and i == 1:
                            continue
                        reason = 'request_errors' if mode == 'mixed' and origin == origins[failed_index] else 'queue_exhausted'
                        rows.append(dict(contract=CONTRACT, origin=origin, stop_reason=reason,
                                         attempted_requests=3, failed_requests=int(reason=='request_errors'),
                                         limited_requests=0, pending_items=0, active_items=0))
                    if mode != 'stale':
                        path.write_text('bad JSON' if mode=='malformed' else '\n'.join(json.dumps(r) for r in rows))
                else:
                    self.assertNotIn('-recon-completion-log', args)
                return SimpleNamespace(returncode=returncode, timed_out=timed_out,
                                       operator_next=operator_next, duration=100, lines=1)
            ctx = self._context(Path(tmp), SimpleNamespace(run=runner))
            # A stale successful artifact must not survive an invocation that writes nothing.
            (ctx.current/'katana-batch-001-completion.jsonl').write_text('stale successful evidence')
            with patch('stages.tool_path', side_effect=lambda t: t=='katana'), patch(
                    'stages._probe_live_origins', return_value=(origins, [])), patch(
                    'stages._katana_completion_supported', return_value=supported), patch(
                    'stages._katana_checkpoint_supported', return_value=checkpoint):
                metrics = stage_urls(ctx)
                if resume:
                    mode = 'complete'
                    if resume_remaining is not None:
                        ctx.budget = MagicMock()
                        ctx.budget.snapshot.return_value = {
                            'http_requests': {'used': 100-resume_remaining, 'limit': 100}
                        }
                    metrics = stage_urls(ctx)
            pending = (ctx.current/'katana-pending-origins.txt').read_text().splitlines()
            completed = (ctx.current/'katana-completed-origins.txt').read_text().splitlines()
            self.assertIn(origins[0]+'/evidence.js', (ctx.current/'katana-urls.txt').read_text())
            return metrics, pending, completed

    def test_explicit_completion_overrides_duration_guard_only_for_supported_producer(self):
        metrics, pending, completed = self.exercise('complete')
        self.assertEqual(pending, [])
        self.assertEqual(len(completed), 2)
        self.assertTrue(metrics['katana_batch_outcomes'][0]['completion_verified'])
        metrics, pending, completed = self.exercise('complete', supported=False)
        self.assertEqual(len(pending), 2)
        self.assertEqual(completed, [])
        self.assertFalse(metrics['katana_batch_outcomes'][0]['completion_verified'])

    def test_valid_sibling_completes_when_other_is_failed_or_missing(self):
        for mode in ('mixed', 'missing'):
            with self.subTest(mode=mode):
                metrics, pending, completed = self.exercise(mode)
                self.assertEqual(completed, ['https://a.example.test'])
                self.assertEqual(pending, ['https://b.example.test'])
                self.assertEqual(metrics['collection_status'], 'partial')
                self.assertFalse(metrics['katana_batch_outcomes'][0]['completion_verified'])

    def test_malformed_and_stale_evidence_preserve_all_pending_origins(self):
        for mode in ('malformed', 'stale'):
            with self.subTest(mode=mode):
                _, pending, completed = self.exercise(mode)
                self.assertEqual(len(pending), 2)
                self.assertEqual(completed, [])

    def test_process_failure_timeout_and_operator_stop_override_success_events(self):
        for flags in ({'returncode':1}, {'timed_out':True}, {'operator_next':True}):
            with self.subTest(flags=flags):
                _, pending, completed = self.exercise('complete', **flags)
                self.assertEqual(len(pending), 2)
                self.assertEqual(completed, [])

    def test_capability_probe_requires_success_and_v1_marker(self):
        for help_text, rc, expected in (
            ('-recon-completion-log EXPERIMENTAL v1 per-origin standard-engine completion JSONL',0,True),
            ('-recon-completion-log',0,False),
            ('-recon-completion-log EXPERIMENTAL v1 per-origin standard-engine completion JSONL',1,False),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                def runner(args, **kwargs):
                    self.assertEqual(args, ['/fake/katana','-h'])
                    self.assertEqual(kwargs['timeout'],5)
                    Path(kwargs['output_path']).write_text(help_text)
                    return SimpleNamespace(returncode=rc,timed_out=False)
                ctx=self._context(Path(tmp),SimpleNamespace(run=runner))
                with patch('stages.tool_path',return_value='/fake/katana'):
                    self.assertEqual(_katana_completion_supported(ctx),expected)

    def test_resume_invokes_only_the_unfinished_contract_origin(self):
        _, pending, completed = self.exercise('mixed', resume=True)
        self.assertEqual(self.last_input_batches, [
            ['https://a.example.test', 'https://b.example.test'],
            ['https://b.example.test'],
        ])
        self.assertEqual(pending, [])
        self.assertEqual(set(completed), {'https://a.example.test', 'https://b.example.test'})

    def test_resume_plans_time_for_backlog_before_allocating_budget(self):
        metrics, pending, completed = self.exercise('mixed', resume=True, origin_count=600)
        self.assertEqual(self.last_input_batches[-1], ['https://b.example.test'])
        self.assertEqual(self.last_crawl_limits[0], 2)
        self.assertEqual(self.last_crawl_limits[-1], 30)
        self.assertEqual(metrics['katana_crawl_seconds_per_origin'], 30)
        self.assertLessEqual(metrics['katana_reserved_requests'], metrics['katana_request_envelope'])
        self.assertEqual(pending, [])
        self.assertEqual(len(completed), 600)

    def test_completed_origins_do_not_take_limited_backlog_admission_slots(self):
        metrics, pending, completed = self.exercise(
            'mixed', resume=True, origin_count=600, failed_index=-1, resume_remaining=6,
        )
        self.assertEqual(self.last_input_batches[-1], ['https://h597.example.test'])
        self.assertLessEqual(metrics['katana_reserved_requests'], 6)
        self.assertLessEqual(metrics['katana_request_envelope'], 6)
        self.assertEqual(pending, [])
        self.assertEqual(len(completed), 600)

    def test_frontier_continuation_keeps_scope_stable_and_old_files(self):
        metrics, pending, completed = self.exercise('mixed', checkpoint=True, resume=True)
        self.assertEqual(pending, [])
        self.assertEqual(len(completed), 2)
        self.assertEqual(self.last_input_batches, [['https://a.example.test'], ['https://b.example.test'], ['https://b.example.test']])
        self.assertEqual(len(set(self.checkpoint_paths)), 1)
        self.assertTrue(all(row['frontier_checkpoint_enabled'] for row in metrics['katana_batch_outcomes']))
        self.assertLessEqual(metrics['katana_reserved_requests'], metrics['katana_request_envelope'])

    def test_frontier_capability_requires_separate_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = SimpleNamespace(current=Path(tmp))
            path = ctx.current / 'katana-completion-capability.txt'
            self.assertFalse(_katana_checkpoint_supported(ctx))
            path.write_text('-recon-checkpoint-dir')
            self.assertFalse(_katana_checkpoint_supported(ctx))
            path.write_text('-recon-checkpoint-dir EXPERIMENTAL v1 durable standard-engine GET frontier checkpoint')
            self.assertTrue(_katana_checkpoint_supported(ctx))
            path.write_bytes(b'\xff')
            self.assertFalse(_katana_checkpoint_supported(ctx))
