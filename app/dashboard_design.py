"""Presentation helpers shared by the existing dashboard renderers.

These helpers preserve native links and forms; no research action is triggered
by opening a menu, expanding filters, or changing appearance.
"""
from __future__ import annotations

import html
from contextlib import contextmanager
from html.parser import HTMLParser
from typing import Any, Mapping
import urllib.parse


MINIMAL_CSS = """
:root{--bg:#10151d;--bg-2:#10151d;--surface:#161d27;--surface-2:#1c2532;--surface-3:#253143;--surface-raised:#161d27;--text:#edf1f7;--muted:#a6b2c3;--faint:#a6b2c3;--border:#2c3746;--border-strong:#43546b;--brand:#92b9ff;--brand-2:#92b9ff;--brand-soft:#233650;--shadow:0 12px 32px #00000033;--shadow-soft:none;--sidebar:178px}
html[data-theme='light']{--bg:#f7f8fa;--bg-2:#f7f8fa;--surface:#fff;--surface-2:#f1f4f8;--surface-3:#e7ecf3;--surface-raised:#fff;--text:#172234;--muted:#536276;--faint:#536276;--border:#e2e7ee;--border-strong:#b9c6d8;--brand:#255ac4;--brand-2:#255ac4;--brand-soft:#e9f0fc;--shadow:0 12px 32px #17223415;--shadow-soft:none;--success:#26634b;--amber:#85520a;--danger:#ad2b46;--orange:#975416;--purple:#7048b5;--info:#255ac4}
body{background:var(--bg);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;letter-spacing:0}
html{scroll-behavior:auto}
.sidebar{display:flex;flex-direction:column;padding:24px 13px 18px;background:var(--surface);box-shadow:none;backdrop-filter:none}.sidebar-footer{margin-top:auto}
.brand{padding:3px 7px 20px;gap:9px}.brand-mark{width:30px;height:30px;background:var(--brand-soft);border:0;border-radius:8px;box-shadow:none;font-weight:600}.brand-mark::before,.brand-mark::after{display:none}.brand-copy strong{font-size:14px;font-weight:600}.brand-copy small{font-size:12px}
.nav-item,.nav-item[data-primary-workspace='1']{display:flex;gap:8px;padding:10px 8px;margin:3px 0;min-height:40px;border:0;border-radius:7px;font-size:13px;font-weight:500}.nav-item.active,.nav-item[data-primary-workspace='1'].active{background:var(--brand-soft);color:var(--brand);box-shadow:none}.nav-item .nav-group-copy strong,.nav-item[data-primary-workspace='1'] .nav-group-copy strong{font-size:13px;font-weight:500;white-space:normal}.nav-item .nav-group-copy small,.nav-item[data-primary-workspace='1'] .nav-group-copy small{display:none}.nav-item>b{display:none}.nav-icon{width:22px;height:22px;border:0;background:transparent;font-size:12px;font-weight:500;color:inherit}.nav-item.active .nav-icon{background:transparent;border:0;color:inherit}.nav-text{white-space:normal}.advanced-nav>summary{padding:10px 8px;grid-template-columns:22px minmax(0,1fr) 12px;gap:8px}.advanced-nav>summary .nav-group-copy strong{font-size:13px;font-weight:500}.advanced-nav>summary small{display:none}.nav-group-icon{border:0;background:transparent;font-size:13px;width:22px;height:22px}.advanced-label{font-size:12px;letter-spacing:0;text-transform:none;padding:12px 8px 4px;font-weight:500}.advanced-nav[open]{background:transparent;border-color:transparent}.sidebar-footer{margin-top:25px}.user-meta small{font-size:12px}
.topbar{height:auto;min-height:65px;padding:12px 26px;background:var(--surface);box-shadow:none;backdrop-filter:none;gap:12px}.view-context{min-width:0}.view-context small{font-size:13px;color:var(--muted)}.view-context strong{display:none}.focus-chip{background:transparent;border:0;padding:0}.focus-chip small{display:none}.focus-chip strong{font-size:13px;font-weight:500}.global-search{flex:1;min-width:130px;max-width:470px;width:auto;margin-left:auto}.global-search input{padding:9px 75px 9px 32px}.search-icon{left:10px;top:8px}.top-actions{margin-left:0}.top-actions .primary-work,.top-actions>.workspace-hero-status{display:none}
.display-menu{position:relative}.display-menu>summary{list-style:none;padding:7px 10px;border:1px solid var(--border);border-radius:7px;font-size:13px;cursor:pointer}.display-menu>summary::-webkit-details-marker{display:none}.display-options{position:absolute;right:0;top:44px;z-index:40;min-width:180px;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);box-shadow:var(--shadow)}.display-options button{width:100%;justify-content:flex-start;margin:3px 0;padding:8px 10px;font-size:13px}.display-options button[aria-pressed='true']{background:var(--brand-soft);color:var(--brand)}
.content{max-width:1440px;padding:25px 28px 48px}.page-header{margin-bottom:20px;gap:15px;align-items:center}h1{font-size:25px;font-weight:500;letter-spacing:-.025em}h2{font-size:15px;font-weight:500}h3{font-size:14px;font-weight:500}.eyebrow{font-size:12px;font-weight:500;letter-spacing:0;text-transform:none;color:var(--muted)}.page-subtitle{font-size:13px;max-width:760px}.breadcrumb{font-size:12px}
button,.button{background:var(--text);color:var(--surface);border:1px solid var(--text);border-radius:7px;font-size:13px;font-weight:500;min-height:36px;padding:8px 11px}button:hover,.button:hover{transform:none;filter:none}button.secondary,.button.secondary{background:var(--surface);color:var(--text);border-color:var(--border)}button.ghost,.button.ghost{color:var(--muted);background:transparent;border-color:var(--border)}input,select,textarea{border-radius:6px;font-size:14px;background:var(--surface)}label{font-size:12px;font-weight:500}
.card,.panel,.metric-card,.attention-card,.workspace-tile,.workspace-hero,.filter-panel,.candidate-card,.confidence-factor,.confidence-verdict,.command-decision,.command-next{background-image:none;box-shadow:none;border-radius:9px}.panel,.card,.metric-card,.attention-card,.workspace-tile,.filter-panel{background:var(--surface)}.panel-head{padding:14px 16px}.panel-body{padding:16px}.metric-card{min-height:100px;padding:14px}.metric-top,.metric-detail,.attention-card small{font-size:12px;font-weight:400}.metric-value{font-size:27px;font-weight:600;margin-top:8px}.metric-spark{display:none}.metric-card:hover,.attention-card:hover,.workspace-tile:hover{transform:none;box-shadow:none}.attention-card strong{font-size:25px;font-weight:600}.workspace-tile-icon{background:var(--surface-2);border:0;font-size:13px}.workspace-tile strong{font-size:14px}.workspace-tile small{font-size:12px}.workspace-hero{padding:16px}.workspace-hero-copy strong{font-size:22px}.workspace-hero-copy small,.workspace-hero-copy p{font-size:12px}
.table-wrap{border-radius:8px}table{min-width:650px}th{font-size:12px;text-transform:none;letter-spacing:0;font-weight:500;color:var(--muted);position:static}td{font-size:13px}th,td{padding:11px 12px}.compact th,.compact td{padding:7px 10px}.row-link{font-weight:500}.pill{font-size:12px;font-weight:500}.small,.filter-head small,.filter-result,.filter-empty,.filter-chip small{font-size:12px}.filter-icon{display:none}.filter-head{border-bottom:0;padding:12px 14px}.filter-panel .filters{padding:0 14px 12px}.filter-grid{display:flex;flex-wrap:wrap;gap:10px;align-items:end}.filter-grid>label{flex:1 1 170px;max-width:330px;min-width:0}.filter-grid>label.filter-wide{flex:2 1 260px;max-width:none}.filter-grid input,.filter-grid select{width:100%;min-width:0}.filter-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.filter-advanced{flex:1 1 100%;width:100%}.filter-advanced>summary{padding:7px 0;color:var(--muted);font-size:13px;cursor:pointer}.filter-advanced-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;padding-top:12px}.filter-advanced-fields>label{min-width:0}.filter-advanced-fields input,.filter-advanced-fields select{width:100%;min-width:0}.filter-summary{padding:0 14px 12px}.filter-chip{background:var(--surface-2);font-weight:500;border:0;border-radius:5px}.filter-chips{flex-wrap:wrap}.quick-view{font-size:12px;font-weight:500;border-radius:6px;background:transparent}.quick-view.active{background:var(--brand-soft);border-color:transparent;color:var(--brand)}.noise-note{font-size:12px;border-style:solid}.callout{font-size:13px;background:var(--surface-2);box-shadow:none}.callout span{font-size:13px}
.candidate-kicker,.candidate-kicker span,.candidate-card small,.candidate-reasoning p,.confidence-factor strong,.confidence-factor small,.confidence-verdict span,.score-triad span,.queue-meta,.section-label small{font-size:12px}.candidate-card h3{font-size:16px}.score-triad strong,.investigation-score strong{font-weight:600}.command-kpi-row{gap:0;margin:20px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}.command-kpi-row .attention-card{border:0;border-radius:0;background:transparent;padding:16px}.command-kpi-row .attention-card+.attention-card{border-left:1px solid var(--border)}.command-decision{padding:12px 14px;min-height:0}.decision-kicker,.decision-meta,.command-decision small,.command-decision-score span,.pulse-row small{font-size:12px}.command-decision strong{font-size:14px;font-weight:500}.command-next{background:var(--surface);border:1px solid var(--border)}.command-next strong{font-size:17px}.command-next small,.command-next p{font-size:13px}.command-v2-grid{gap:18px}.command-pulse{padding:0 16px}.pulse-row{padding:12px 0}.pulse-row b{font-weight:500}.change-event small,.change-event span{font-size:12px}
.workspace-access{display:block;width:max-content;max-width:100%;margin:0 0 12px auto;position:relative;border:0;border-radius:0;background:transparent;overflow:visible}.workspace-access>summary{list-style:none;padding:5px 0;font-size:13px;color:var(--muted);cursor:pointer}.workspace-access>summary::-webkit-details-marker{display:none}.workspace-access-links{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px;position:absolute;right:0;top:34px;z-index:15;width:min(700px,calc(100vw - var(--sidebar) - 64px));padding:12px;border:1px solid var(--border);border-radius:9px;background:var(--surface);box-shadow:var(--shadow)}.workspace-access-links a{font-size:13px;padding:8px;border-radius:5px;overflow-wrap:anywhere}.workspace-access-links a:hover,.workspace-access-links a[aria-current='page']{background:var(--brand-soft);color:var(--brand)}
.run-status-strip{display:flex;align-items:center;gap:10px 16px;flex-wrap:wrap;padding:14px 16px;border:1px solid var(--border);border-radius:9px;background:var(--surface);margin-bottom:18px}.run-status-strip .run-status-copy{flex:1;min-width:180px}.run-status-copy strong{font-size:14px;font-weight:500}.run-status-copy small{display:block;font-size:12px;color:var(--muted);margin-top:3px}.run-status-error{flex-basis:100%;font-size:13px;color:var(--amber);overflow-wrap:anywhere}.run-stage-summary{margin:18px 0}.run-stage-summary table{min-width:680px}.pager{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:16px 0;font-size:13px}.search-groups{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:18px}.search-group{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px}.search-group.active{background:var(--brand-soft);color:var(--brand);border-color:transparent}.search-context{font-size:12px;color:var(--muted);overflow-wrap:anywhere}.query-result-count{font-variant-numeric:tabular-nums}
@media(max-width:1120px){.topbar{padding:10px 20px}.command-kpi-row .attention-card:nth-child(3){border-left:0}.workspace-access-links{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){:root{--sidebar:230px}.topbar{padding:10px 14px;gap:8px}.content{padding:20px 16px 40px}.global-search{max-width:none}.shortcut{display:none}.global-search input{padding-right:10px}.command-kpi-row{grid-template-columns:repeat(2,minmax(0,1fr))}.command-kpi-row .attention-card{padding:13px}.command-kpi-row .attention-card:nth-child(odd){border-left:0}.display-options{right:0}.workspace-access-links{width:100%}.filter-grid>label{max-width:none;flex:1 1 160px}.filter-advanced-fields{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}.filter-grid .filter-actions{width:100%}.filter-head{flex-wrap:wrap}.filter-result{white-space:normal}.command-decision{grid-template-columns:25px minmax(0,1fr) 48px}.command-decision>i{display:none}}
@media(max-width:420px){.workspace-access-links{grid-template-columns:1fr}.command-kpi-row{grid-template-columns:1fr 1fr}.page-actions{gap:6px}.page-actions .button{font-size:12px}.filter-advanced-fields{grid-template-columns:1fr}.run-status-copy{min-width:0}}
@media(pointer:coarse){button,.button,summary{min-height:44px}input,select,textarea{font-size:16px;min-height:44px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
.command-primary-action{background:var(--surface);box-shadow:none;border:1px solid var(--border);border-radius:9px}.command-primary-action small,.decision-copy small,.decision-copy em,.decision-score small{font-size:12px;font-weight:500;letter-spacing:0;text-transform:none}.decision-copy span{font-size:13px}.decision-rank{font-size:12px;border:0;background:transparent}.command-decision:hover{transform:none;box-shadow:none}.change-event>i{box-shadow:none}.search-groups>a{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px}.search-groups>a.active{background:var(--brand-soft);color:var(--brand);border-color:transparent}.guidance-details>summary{cursor:pointer;font-weight:500}.guidance-details>summary .small{font-weight:400}
.command-kpi-row .attention-item{background:transparent;border:0;border-radius:0;box-shadow:none;padding:16px 12px;min-height:0;grid-template-columns:24px minmax(0,1fr) auto}.command-kpi-row .attention-item+.attention-item{border-left:1px solid var(--border)}.attention-item strong{font-size:14px;font-weight:500}.attention-item small,.decision-copy span,.decision-copy em{font-size:12px;white-space:normal;overflow:visible;text-overflow:clip;overflow-wrap:anywhere}.attention-item::after{display:none}.attention-icon{background:transparent;border:0;box-shadow:none;width:24px;height:24px}.attention-item>b{font-size:25px;font-weight:600}.attention-item:hover{transform:none;box-shadow:none}.command-kpi-row .attention-item>i{display:none}.command-item strong,.command-item small{font-size:13px}.command-key{font-size:12px}
.search-record-details summary{cursor:pointer;font-size:13px}.search-record-details dl{display:grid;grid-template-columns:minmax(100px,180px) minmax(0,1fr);gap:8px 14px}.search-record-details dt{font-size:12px;color:var(--muted)}.search-record-details dd{margin:0;min-width:0}.search-record-details pre{margin:0;background:var(--surface-2);padding:8px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
.attention-card{display:flex;flex-direction:column;gap:6px;min-width:0;padding:14px;border:1px solid var(--border)}.attention-card>span,.attention-card>small{color:var(--muted);font-size:12px}.attention-card strong{overflow-wrap:anywhere;line-height:1.25}#analysis-fast-summary .attention-card strong{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.display-menu{border:0;background:transparent;overflow:visible}.guidance-details>summary{padding:0}.progress-heading{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.progress-context,.queue-context{display:flex;gap:6px 14px;flex-wrap:wrap;align-items:center;font-size:12px;color:var(--muted)}.progress-context code,.queue-context code{overflow-wrap:anywhere}.progress-detail{border:0;border-radius:0;background:transparent}.progress-detail>summary{padding:9px 0;color:var(--muted);font-size:13px;font-weight:500}.progress-detail>.details-body{padding:12px 0 0}.progress-summary{padding:0 16px 10px}.progress-alert{margin:8px 0;font-size:13px;color:var(--amber);overflow-wrap:anywhere}.progress-overview{display:grid;grid-template-columns:minmax(120px,.65fr) minmax(0,1.5fr) minmax(100px,.65fr);gap:14px}.progress-overview>div{min-width:0}.progress-overview span,.progress-overview small{display:block;color:var(--muted);font-size:12px}.progress-overview strong{display:block;font-size:18px;font-weight:500;overflow-wrap:anywhere}.progress-bar{height:6px;background:var(--surface-3);border-radius:6px;overflow:hidden;margin:12px 0}.progress-bar>div{height:100%;background:var(--brand)}.queue-counts{display:flex;gap:8px 20px;flex-wrap:wrap;font-size:13px}.queue-counts strong{font-weight:500}.queue-empty-copy{margin:8px 0;color:var(--muted);font-size:13px}.queue-method{margin-top:8px;border:0;background:transparent}.queue-method>summary{padding:8px 0;font-size:13px;font-weight:500;color:var(--muted)}.queue-method>.details-body{padding:12px 0}.queue-method p{margin:10px 0 0;font-size:13px;color:var(--muted)}
@media(max-width:820px){.workspace-access-links{width:min(700px,calc(100vw - 32px))}.progress-overview{grid-template-columns:1fr 1fr}.progress-overview>div:nth-child(2){grid-column:1/-1;grid-row:2}}
@media(max-width:1120px){.command-kpi-row .attention-item:nth-child(3){border-left:0}}@media(max-width:820px){.command-kpi-row .attention-item{padding:12px 8px;gap:8px}.command-kpi-row .attention-item:nth-child(odd){border-left:0}.command-v2-grid{grid-template-columns:1fr}.command-primary-action h2{font-size:18px}}
.sidebar-footer{margin-top:auto}.brand-copy strong{font-weight:500}.global-search{max-width:330px}
.command-balanced .page-header{margin:0 0 18px}.command-context-form{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 18px}.command-context-form label{display:flex;gap:9px;align-items:center;font-size:13px;color:var(--muted)}.command-context-form select{min-width:150px;max-width:100%;padding:7px 9px;font-size:13px}.command-text-link{font-size:13px;color:var(--brand)}.command-balanced .run-status-copy{display:flex;gap:9px 12px;align-items:center;flex-wrap:wrap;min-width:0}.command-balanced .run-status-copy strong{font-size:13px;font-weight:500;overflow-wrap:anywhere}.command-balanced .run-status-copy small{margin:0;font-size:12px}.command-balanced .run-status-error{color:var(--muted);font-size:13px}.command-no-run{font-size:13px;color:var(--muted);padding:10px 0 14px}
.command-saved-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));margin:24px 0 27px}.command-saved-metric{min-width:0;border-left:1px solid var(--border);padding:3px 22px}.command-saved-metric:first-child{border-left:0;padding-left:0}.command-saved-metric>span{display:block;font-size:13px;color:var(--muted)}.command-saved-metric>strong{display:block;margin-top:3px;font-size:29px;line-height:1.2;font-weight:500;font-variant-numeric:tabular-nums}.command-saved-metric>small{display:block;font-size:12px;color:var(--muted);margin-top:5px;overflow-wrap:anywhere}.command-saved-metric:hover>span{color:var(--brand)}
.command-balanced-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:20px;align-items:start}.command-balanced-panel{min-width:0}.command-balanced-panel>.panel-head{padding:17px 18px 0;border:0;min-height:0}.command-balanced-panel>.panel-head h2{margin:0}.command-balanced-panel>.panel-body{padding:10px 18px 17px}.command-attention-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 0;border-top:1px solid var(--border);font-size:13px}.command-attention-row>span:first-child{min-width:0}.command-attention-row strong{display:block;font-size:14px;font-weight:500;overflow-wrap:anywhere}.command-attention-row small{display:block;margin-top:3px;font-size:12px;color:var(--muted);overflow-wrap:anywhere}.command-attention-row:hover strong{color:var(--brand)}.command-row-end{display:flex;align-items:center;gap:9px;flex-shrink:0;font-variant-numeric:tabular-nums}.command-row-end i{font-style:normal;color:var(--muted)}.command-inventory-row{display:flex;justify-content:space-between;align-items:baseline;gap:9px;padding:9px 0;border-bottom:1px solid var(--border);font-size:13px}.command-inventory-row strong{font-weight:500;font-variant-numeric:tabular-nums}.command-inventory-row:hover{color:var(--brand)}
.command-review-summary{display:flex;gap:6px 15px;flex-wrap:wrap;margin:12px 0 5px;font-size:12px;color:var(--muted)}.command-review-summary a:hover{color:var(--brand)}.command-details{border:0;border-top:1px solid var(--border);background:transparent;border-radius:0;margin-top:10px}.command-details>summary{padding:10px 0;font-size:13px;font-weight:500;color:var(--muted);cursor:pointer}.command-details>p{margin:5px 0 12px}.command-details .command-decision-list{gap:0}.command-details .command-decision{border:0;border-top:1px solid var(--border);border-radius:0;background:transparent;padding:12px 0;grid-template-columns:25px minmax(0,1fr) 48px 12px;gap:9px}.command-details .decision-rank{width:auto;height:auto}.command-details .decision-copy small{font-weight:400}.command-details .decision-score b{font-size:18px;font-weight:500}.command-next-row{padding:12px 0;border-top:1px solid var(--border);font-size:13px}.command-next-row>small{display:block;color:var(--muted);font-size:12px}.command-next-row>a{display:block;margin-top:3px;font-weight:500}.command-next-row>p{margin:5px 0;color:var(--muted);font-size:12px}.command-tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;padding-top:12px}.command-tools form{margin:0}.command-balanced .command-pulse{padding:0}.command-recent{margin-top:22px}.command-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.command-section-head h2{margin:0}.command-recent .command-attention-row{padding:11px 0}.command-recent .change-stream{gap:0}.command-recent .change-event{border:0;border-top:1px solid var(--border);border-radius:0;padding:11px 0;background:transparent}.command-recent .change-event span{white-space:normal;overflow:visible;overflow-wrap:anywhere}.command-footer{padding-top:23px;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
@media(max-width:850px){.command-balanced-grid{grid-template-columns:1fr}.command-balanced .page-header{flex-wrap:wrap}.command-context-form label{flex-wrap:wrap}}@media(max-width:560px){.command-saved-metric{padding:3px 12px}.command-saved-metric>strong{font-size:25px}.command-saved-metric>span{font-size:12px}.command-balanced-panel>.panel-head{padding:15px 15px 0}.command-balanced-panel>.panel-body{padding:10px 15px 15px}.command-balanced .run-status-copy{flex-basis:100%}.command-context-form label{width:100%}.command-context-form select{flex:1;min-width:0}.command-details .command-decision{grid-template-columns:20px minmax(0,1fr) 40px}.command-details .command-decision>i{display:none}.global-search{max-width:none}}
.search-type-browser{border:0;border-bottom:1px solid var(--border);border-radius:0;background:transparent;margin:14px 0 18px}.search-type-browser>summary{padding:9px 0;cursor:pointer;font-size:13px;font-weight:500}.search-type-browser>summary .small{margin-left:10px;color:var(--muted);font-weight:400;overflow-wrap:anywhere}.search-type-browser .search-groups{margin:9px 0 14px}.search-results-panel{margin-top:16px;min-width:0}.search-results-panel>.panel-head{flex-wrap:wrap;gap:6px 14px}.search-results-panel>.table-wrap{border:0;border-radius:0}.record-field-label{display:none}.responsive-records td{overflow-wrap:anywhere}.responsive-records code{white-space:normal;overflow-wrap:anywhere}.record-field-value{min-width:0}.run-observations{list-style:none;margin:0;padding:0}.run-observations li+li{margin-top:4px}.run-review-summary{padding:16px;min-width:0}.run-review-summary h2{margin:0;line-height:1.5}.run-review-summary p{margin:9px 0 0;overflow-wrap:anywhere}.run-review-summary code{white-space:normal;overflow-wrap:anywhere}.run-stage-summary>.table-wrap{border:0;border-radius:0}.run-stage-summary .panel-head{flex-wrap:wrap;gap:6px 14px}
@media(max-width:680px){.responsive-records,.run-stage-summary .responsive-records{display:block;min-width:0;width:100%}.responsive-records thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}.responsive-records tbody{display:block}.responsive-records tbody>tr{display:block;padding:12px 15px;border-bottom:1px solid var(--border)}.responsive-records tbody>tr:last-child{border-bottom:0}.responsive-records td,.compact .responsive-records td{display:block;border:0;padding:5px 0;max-width:none;width:100%}.responsive-records .record-field-label{display:block;margin-bottom:2px;color:var(--muted);font-size:12px;font-weight:500}.search-record-details dl{grid-template-columns:1fr;gap:4px}.search-record-details dd{margin-bottom:10px}.search-record-details pre{max-width:100%}.search-type-browser>summary .small{display:block;margin:4px 0 0}}
"""


def labeled_cell(label: str, markup: str) -> str:
    """Render caller-prepared HTML once and label the field when rows stack."""
    return (
        "<td role='cell'><span class='record-field-label' aria-hidden='true'>"
        + html.escape(label)
        + "</span><div class='record-field-value'>" + markup + "</div></td>"
    )


class _FieldSplitter(HTMLParser):
    """Keep generated field markup byte-for-byte, including hidden selectors."""

    def __init__(self, markup: str):
        super().__init__(convert_charrefs=False)
        self.markup = markup
        self.lines = [0]
        for index, char in enumerate(markup):
            if char == '\n':
                self.lines.append(index + 1)
        self.labels: list[tuple[int, int, str]] = []
        self.open_label: tuple[int, str] | None = None
        self.depth = 0
        self.feed(markup)

    def absolute_offset(self) -> int:
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == 'label':
            if self.depth == 0:
                self.open_label = (self.absolute_offset(), '')
            self.depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == 'label' and self.depth:
            self.depth -= 1
            if self.depth == 0 and self.open_label:
                start = self.open_label[0]
                end = self.markup.find('>', self.absolute_offset()) + 1
                self.labels.append((start, end, self.markup[start:end]))
                self.open_label = None


def split_filter_fields(markup: str) -> tuple[str, str]:
    """Search/Target stay visible; every other generated label stays in the form."""
    parser = _FieldSplitter(markup)
    basic, advanced = [], []
    previous = 0
    for start, end, label in parser.labels:
        basic.append(markup[previous:start])
        probe = _ControlNames()
        probe.feed(label)
        (basic if probe.names & {'q', 'target'} else advanced).append(label)
        previous = end
    basic.append(markup[previous:])
    return ''.join(basic), ''.join(advanced)


class _ControlNames(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {'input', 'select', 'textarea'}:
            name = dict(attrs).get('name')
            if name:
                self.names.add(name)


@contextmanager
def read_snapshot(db: Any):
    """Keep counts and rows on one read snapshot without taking a writer lock."""
    with db._lock:
        own = not db.conn.in_transaction
        if own: db.conn.execute('BEGIN')
        try:
            yield
        finally:
            if own: db.conn.execute('ROLLBACK')


def query_page(db: Any, sql: str, args: Any, params: Mapping[str, Any], *, page_key: str = 'page', page_size: int = 100) -> tuple[list[Any], int, int]:
    """Count the complete filtered SELECT; fetch only the requested page."""
    with read_snapshot(db):
        total = int(db.one('SELECT COUNT(*) FROM (' + sql + ')', args)[0])
        try:
            requested = int((params.get(page_key) or [1])[0])
        except (TypeError, ValueError):
            requested = 1
        page = max(1, min(requested, max(1, (total + page_size - 1) // page_size)))
        rows = db.all(sql + ' LIMIT ? OFFSET ?', (*args, page_size, (page - 1) * page_size))
    return rows, total, page


def pagination(path: str, params: Mapping[str, Any], total: int, page: int, page_size: int, *, page_key: str = 'page') -> str:
    if total <= page_size:
        return ''
    pages = max(1, (total + page_size - 1) // page_size)
    def link(number: int, label: str) -> str:
        query = {key: value for key, value in params.items() if value is not None and value != ''}
        query[page_key] = number
        href = path + '?' + urllib.parse.urlencode(query)
        return f"<a class='button ghost' href='{html.escape(href, quote=True)}'>{label}</a>"
    return (
        "<nav class='pager' aria-label='Results pages'>"
        + (link(page - 1, 'Previous') if page > 1 else '<span></span>')
        + f"<span class='query-result-count'>Page {page} of {pages} · {total} results</span>"
        + (link(page + 1, 'Next') if page < pages else '<span></span>')
        + '</nav>'
    )
