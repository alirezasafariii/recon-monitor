// Installed before application scripts. Records marker reachability, never values.
({marker}) => {
  const record = sink => {
    if (window.__rmSink) window.__rmSink({marker, sink}).catch(() => {});
  };
  for (const name of ['innerHTML', 'outerHTML']) {
    const d = Object.getOwnPropertyDescriptor(Element.prototype, name);
    if (d && d.set) Object.defineProperty(Element.prototype, name, {...d, set(value) {
      if (typeof value === 'string' && value.includes(marker)) record(name.toLowerCase());
      return d.set.call(this, value);
    }});
  }
  const insert = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function(position, value) {
    if (typeof value === 'string' && value.includes(marker)) record('insertadjacenthtml');
    return insert.call(this, position, value);
  };
  for (const name of ['write', 'writeln']) {
    const original = Document.prototype[name];
    Document.prototype[name] = function(...values) {
      if (values.some(v => typeof v === 'string' && v.includes(marker))) record('document_' + name);
      return original.apply(this, values);
    };
  }
}
