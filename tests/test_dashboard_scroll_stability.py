from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from dashboard import _layout


class DashboardScrollStabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = _layout(
            "Run review",
            "<section class='panel'><details data-detail-id='urls'>"
            "<summary>URL crawl</summary><p>Partial</p></details></section>",
            current_path="/recon?view=overview",
        )

    def test_details_are_native_in_page_and_do_not_use_hash_links(self) -> None:
        self.assertIn("<details data-detail-id='urls'>", self.html)
        self.assertIn("<summary>URL crawl</summary>", self.html)
        self.assertNotIn("href='#'", self.html)

    def test_get_filters_restore_reading_position_without_exact_query_match(self) -> None:
        html = self.html
        self.assertIn("recon-filter-scroll-v2", html)
        self.assertIn("pending.path===here", html)
        self.assertNotIn("previous.destination===here", html)
        self.assertIn("form.method.toLowerCase()!=='get'", html)
        self.assertIn("remember(next.pathname,form)", html)
        self.assertIn("form.getBoundingClientRect().top", html)
        self.assertIn("filter.getBoundingClientRect().top-pending.filterTop", html)
        self.assertIn("main.content form.filters", html)
        self.assertIn("window.scrollTo(0,Math.max(0,y))", html)
        self.assertIn("window.addEventListener('pageshow'", html)
        self.assertIn("window.addEventListener('load'", html)
        self.assertIn("requestAnimationFrame(()=>requestAnimationFrame(restore))", html)
        self.assertIn("!window.location.hash", html)
        self.assertIn("next.pathname!==here", html)

    def test_live_refresh_preserves_expansion_focus_and_scroll(self) -> None:
        html = self.html
        self.assertIn("fresh.innerHTML!==panel.innerHTML", html)
        self.assertIn("const expanded=oldDetails.map", html)
        self.assertIn("counterpart.open=item.open", html)
        self.assertIn("focused?.focus({preventScroll:true})", html)
        self.assertIn("window.scrollTo(0,priorScroll+delta)", html)
        self.assertIn("panel.replaceWith(fresh)", html)

    def test_refresh_does_not_rewrite_entire_document(self) -> None:
        self.assertNotIn("window.location.reload()", self.html)
        self.assertNotIn("document.body.innerHTML=payload.html", self.html)


if __name__ == "__main__":
    unittest.main()
