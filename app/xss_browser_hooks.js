// Runtime reachability instrumentation. Native calls and exceptions are preserved.
({marker, allowedOrigin}) => {
  // Do not count execution in opaque sandboxed srcdoc as execution in the target.
  const binding = window.__rmXss;
  window.__rmXss = token => self.origin === allowedOrigin ? binding(token) : Promise.resolve();
  addEventListener('securitypolicyviolation', event => {
    if (window.__rmControl) window.__rmControl({directive:event.effectiveDirective,
      disposition:event.disposition, marker_related:typeof event.sample === 'string' && event.sample.includes(marker)}).catch(() => {});
  });
  const seen = new Set();
  const report = (sink, value) => {
    if (typeof value !== 'string' || !value.includes(marker)) return;
    // Deduplicate repeated observations of the same sink in this document.
    if (seen.has(sink)) return;
    seen.add(sink);
    if (window.__rmSink) window.__rmSink({marker, sink}).catch(() => {});
  };
  const setter = (prototype, name, sink) => {
    if (!prototype) return;
    const d = Object.getOwnPropertyDescriptor(prototype, name);
    if (!d || !d.set || !d.configurable) return;
    Object.defineProperty(prototype, name, {...d, set(value) {
      report(sink, value);
      return Reflect.apply(d.set, this, [value]);
    }});
  };
  const method = (prototype, name, sink, indexes) => {
    if (!prototype || typeof prototype[name] !== 'function') return;
    const original = prototype[name];
    prototype[name] = function(...args) {
      for (const index of indexes) report(sink, args[index]);
      return Reflect.apply(original, this, args);
    };
  };
  setter(Element.prototype, 'innerHTML', 'innerhtml');
  setter(Element.prototype, 'outerHTML', 'outerhtml');
  setter(window.ShadowRoot && ShadowRoot.prototype, 'innerHTML', 'shadow_innerhtml');
  setter(window.HTMLIFrameElement && HTMLIFrameElement.prototype, 'srcdoc', 'iframe_srcdoc');
  method(Element.prototype, 'insertAdjacentHTML', 'insertadjacenthtml', [1]);
  method(Range.prototype, 'createContextualFragment', 'contextual_fragment', [0]);
  const parse = DOMParser.prototype.parseFromString;
  DOMParser.prototype.parseFromString = function(value, type) {
    if (type === 'text/html') report('domparser_html', value);
    return Reflect.apply(parse, this, [value, type]);
  };
  method(Element.prototype, 'setHTMLUnsafe', 'sethtmlunsafe', [0]);
  method(window.ShadowRoot && ShadowRoot.prototype, 'setHTMLUnsafe', 'sethtmlunsafe', [0]);
  for (const name of ['write', 'writeln']) {
    const original = Document.prototype[name];
    Document.prototype[name] = function(...values) {
      for (const value of values) report('document_' + name, value);
      return Reflect.apply(original, this, values);
    };
  }
  const attribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (typeof name === 'string') {
      const key = name.toLowerCase();
      if (key === 'srcdoc') report('iframe_srcdoc', value);
      else if (key.startsWith('on')) report('event_handler_attribute', value);
      else if (['href', 'src', 'action', 'formaction'].includes(key)) report('url_attribute', value);
    }
    return Reflect.apply(attribute, this, [name, value]);
  };
}
