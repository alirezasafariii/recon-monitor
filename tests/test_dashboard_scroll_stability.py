from __future__ import annotations

import sys
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from dashboard import _inject_filter_anchors, _layout


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
        self.assertIn("form class='filters filter-grid' method='get' id='filter-1' action='#filter-1'", html)
        self.assertIn("form.filters[id]{scroll-margin-top:86px}", html)
        self.assertIn("form.matches('form.filters')", html)
        self.assertIn("form.method.toLowerCase()!=='get'", html)
        self.assertIn("event.preventDefault()", html)
        self.assertIn("next.search=new URLSearchParams(new FormData(form)).toString()", html)
        self.assertIn("action='#filter-1'", html)
        self.assertIn("window.location.assign(next.href)", html)
        self.assertNotIn("recon-filter-scroll-v2", html)
        self.assertNotIn("sessionStorage.setItem", html)

    def test_filter_anchor_is_rendered_before_client_script_runs(self) -> None:
        html = self.html
        form_pos = html.index("id='filter-1'")
        script_pos = html.index("<script>")
        self.assertLess(form_pos, script_pos)

    def test_native_get_anchor_requires_no_script_and_preserves_unrelated_forms(self) -> None:
        body = (
            "<form class='filters filter-grid' method='get'><button>Apply filters</button></form>"
            "<form class='filters' method='GET'><button>Filter</button></form>"
            "<form class='filters' method='post'><button>Save</button></form>"
            "<form class='other' method='get'><button>Other</button></form>"
        )
        rendered = _inject_filter_anchors(body)
        self.assertIn("method='get' id='filter-1' action='#filter-1'", rendered)
        self.assertIn("method='GET' id='filter-2' action='#filter-2'", rendered)
        self.assertIn("<form class='filters' method='post'>", rendered)
        self.assertIn("<form class='other' method='get'>", rendered)
        self.assertNotIn("<script", rendered)

    def test_explicit_get_action_is_preserved(self) -> None:
        body = "<form class='filters' method='get' action='/audit'><button>Apply</button></form>"
        result = _inject_filter_anchors(body)
        self.assertIn("id='filter-1'", result)
        self.assertIn("action='/audit'", result)
        self.assertNotIn("action='#filter-1'", result)

    def test_recon_filter_uses_in_place_get_without_full_reload(self) -> None:
        html = self.html
        self.assertIn("window.location.pathname!=='/recon'", html)
        self.assertIn("document.addEventListener('submit'", html)
        self.assertIn("event.preventDefault()", html)
        self.assertIn("void updateRecon(next,opts)", html)
        self.assertIn("await fetch(next.pathname+next.search", html)
        self.assertIn("const replacement=page.querySelector('main.content')", html)
        self.assertIn("current.replaceWith(replacement)", html)
        self.assertIn("history.pushState(", html)
        self.assertIn("window.addEventListener('popstate'", html)
        self.assertIn("form.getBoundingClientRect().top", html)
        self.assertIn("jumpTo(desiredY)", html)
        self.assertIn("window.location.assign(next.href)", html)

    def test_live_refresh_preserves_expansion_focus_and_scroll(self) -> None:
        html = self.html
        self.assertIn("fresh.innerHTML!==panel.innerHTML", html)
        self.assertIn("const expanded=oldDetails.map", html)
        self.assertIn("counterpart.open=item.open", html)
        self.assertIn("focused?.focus({preventScroll:true})", html)
        self.assertIn("window.scrollTo(0,priorScroll+delta)", html)
        self.assertIn("panel.replaceWith(fresh)", html)

    def test_refresh_does_not_rewrite_entire_document(self) -> None:
        self.assertIn("window.location.reload()", self.html)  # only on failed back/forward fetch
        self.assertIn("if(options.push)", self.html)
        self.assertNotIn("document.body.innerHTML=payload.html", self.html)


if __name__ == "__main__":
    unittest.main()
