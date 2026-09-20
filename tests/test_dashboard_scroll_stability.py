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
            "<section class='panel'><form class='filters filter-grid' method='get'>"
            "<label>Target<input name='target' value='example.test'></label>"
            "<button>Apply filters</button></form>"
            "<details data-detail-id='urls'><summary>URL crawl</summary>"
            "<p>Partial</p></details></section>",
            current_path="/recon?view=overview",
        )

    def test_details_are_native_in_page_and_do_not_use_hash_links(self) -> None:
        self.assertIn("<details data-detail-id='urls'>", self.html)
        self.assertIn("<summary>URL crawl</summary>", self.html)
        self.assertNotIn("href='#'", self.html)

    def test_get_filters_use_server_rendered_fragment_anchor(self) -> None:
        html = self.html
        self.assertIn("form class='filters filter-grid' method='get' id='filter-1'", html)
        self.assertIn("form.filters[id]{scroll-margin-top:86px}", html)
        self.assertIn("form.matches('form.filters')", html)
        self.assertIn("form.method.toLowerCase()!=='get'", html)
        self.assertIn("event.preventDefault()", html)
        self.assertIn("next.search=new URLSearchParams(new FormData(form)).toString()", html)
        self.assertIn("next.hash=form.id", html)
        self.assertIn("window.location.assign(next.href)", html)
        self.assertNotIn("recon-filter-scroll-v2", html)
        self.assertNotIn("sessionStorage.setItem", html)

    def test_filter_anchor_is_rendered_before_client_script_runs(self) -> None:
        html = self.html
        form_pos = html.index("id='filter-1'")
        script_pos = html.index("<script>")
        self.assertLess(form_pos, script_pos)

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
