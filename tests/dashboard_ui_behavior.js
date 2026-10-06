/* Execute the production scroll/polling code with controlled DOM boundaries.
 * This checks behavior without a browser dependency or any network request.
 */
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(0, 'utf8');
const scrollSource = source.slice(source.indexOf('(function(){'), source.indexOf('window.RECON_CSRF'));
const pollingSource = source.slice(source.indexOf('async function refreshLiveProgress(){'), source.indexOf('if(liveProgressKind){'));

function scrollContext(saved = null, hash = '') {
  const events = {};
  const storage = new Map(saved ? [['recon-same-page-scroll', JSON.stringify(saved)]] : []);
  const scrolls = [];
  class Element {
    constructor(link) { this.link = link; }
    closest() { return this.link; }
  }
  class Form extends Element {
    constructor(method, fields, action = 'http://localhost/recon') {
      super({}); this.method = method; this.fields = fields; this.action = action;
      this.attributes = {method, action, target: ''};
      for (const [name] of fields) if (['target','method','action'].includes(name)) this[name] = {tagName:'INPUT'};
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
  }
  const ctx = {
    URL, URLSearchParams, Element, HTMLFormElement: Form,
    FormData: class { constructor(form) { return form.fields; } },
    sessionStorage: { getItem: k => storage.get(k) || null, removeItem: k => storage.delete(k), setItem: (k,v) => storage.set(k,v) },
    requestAnimationFrame: fn => fn(),
    document: { documentElement: {style: {scrollBehavior: 'auto'}}, addEventListener: (name, fn) => events[name] = fn },
    window: { history: {scrollRestoration: 'auto'}, location: {href: 'http://localhost/recon?q=old' + hash, pathname: '/recon', search: '?q=old', origin: 'http://localhost', hash}, scrollY: 500, scrollTo: (x,y) => scrolls.push(y), addEventListener: (name,fn) => events[name] = fn },
  };
  vm.createContext(ctx); vm.runInContext(scrollSource, ctx);
  return {ctx, events, storage, scrolls, Element, Form};
}

function click(env, href, extras = {}) {
  const link = {href, hasAttribute: () => false, target: ''};
  env.events.click({target: new env.Element(link), button: 0, defaultPrevented: false, ...extras});
}

async function pollingContext({focus = false, selected = false, above = true, visible = true, fail = false, disclosureOpen = false} = {}) {
  let fetches = 0, replacements = 0;
  const active = {};
  const anchor = {};
  const scrolls = [];
  const nextDisclosure = {open: !disclosureOpen};
  const fresh = {getBoundingClientRect: () => ({height: 140}), querySelector: selector => {
    assert.equal(selector, '#live-progress-details'); return nextDisclosure;
  }};
  const panel = {
    contains: node => (focus && node === active) || (selected && node === anchor),
    getBoundingClientRect: () => ({height: 100, bottom: above ? 0 : 600}),
    querySelectorAll: selector => {
      assert.equal(selector, 'details[id]'); return [{id: 'live-progress-details', open: disclosureOpen}];
    },
    replaceWith: node => {assert.equal(node, fresh); replacements++;},
  };
  const ctx = {
    URLSearchParams, console: {debug() {}},
    window: {location: {search: '?target=example.test'}, scrollY: 500, scrollTo: (x,y) => scrolls.push(y), getSelection: () => ({isCollapsed: !selected, anchorNode: anchor, focusNode: anchor})},
    document: {
      activeElement: active, visibilityState: visible ? 'visible' : 'hidden',
      getElementById: () => panel,
      querySelector: () => ({getBoundingClientRect: () => ({bottom: 65})}),
      createElement: () => ({content: {querySelector: () => fresh}}),
    },
    fetch: async (url, opts) => {
      fetches++;
      assert.equal(url, '/api/live-progress?kind=recon&target=example.test');
      assert.equal(opts.credentials, 'same-origin');
      return {ok: !fail, status: fail ? 500 : 200, headers: {get: () => 'application/json'}, json: async () => ({html: '<section id="live-progress"></section>'})};
    },
  };
  vm.createContext(ctx);
  vm.runInContext("const liveProgressKind='recon';let liveProgressBusy=false;" + pollingSource, ctx);
  await ctx.refreshLiveProgress();
  assert.equal(vm.runInContext('liveProgressBusy', ctx), false);
  assert.equal(ctx.document.activeElement, active);
  return {fetches, replacements, scrolls, ctx, nextDisclosure};
}

(async () => {
  const restored = scrollContext({next:'/recon?q=old', y:725});
  assert.deepEqual(restored.scrolls, [725]);
  restored.events.load(); assert.deepEqual(restored.scrolls, [725,725]);
  assert.equal(scrollContext({next:'/analysis',y:725}).scrolls.length, 0);
  assert.equal(scrollContext({next:'/recon?q=old',y:725}, '#evidence').scrolls.length, 0);

  const same = scrollContext(); click(same, 'http://localhost/recon?q=new&target=example.test');
  assert.deepEqual(JSON.parse(same.storage.get('recon-same-page-scroll')), {next:'/recon?q=new&target=example.test',y:500});
  for (const url of ['http://localhost/analysis?q=new','http://other.test/recon?q=new','http://localhost/recon?q=new#evidence']) {
    const env = scrollContext(); click(env, url); assert.equal(env.storage.size, 0);
  }
  const modified = scrollContext(); click(modified, 'http://localhost/recon?q=new', {metaKey:true}); assert.equal(modified.storage.size, 0);

  const get = scrollContext();
  get.events.submit({target:new get.Form('get', [['q','a&b'],['source','katana'],['target','example.test']])});
  assert.deepEqual(JSON.parse(get.storage.get('recon-same-page-scroll')), {next:'/recon?q=a%26b&source=katana&target=example.test',y:500});
  const named = scrollContext();
  named.events.submit({target:new named.Form('get', [['target','example.test'],['method','literal'],['action','recorded']])});
  assert.deepEqual(JSON.parse(named.storage.get('recon-same-page-scroll')), {next:'/recon?target=example.test&method=literal&action=recorded',y:500});
  const newTab = scrollContext(), newTabForm = new newTab.Form('get', [['target','example.test']]);
  newTabForm.attributes.target = '_blank';
  newTab.events.submit({target:newTabForm}); assert.equal(newTab.storage.size, 0);
  const post = scrollContext(); post.events.submit({target:new post.Form('post', [['run_id','R1']])}); assert.equal(post.storage.size, 0);

  for (const opts of [{focus:true},{selected:true}]) {
    const env = await pollingContext(opts); assert.equal(env.fetches,1); assert.equal(env.replacements,0); assert.equal(env.scrolls.length,0);
  }
  const above = await pollingContext(); assert.equal(above.replacements,1); assert.deepEqual(above.scrolls,[540]);
  const below = await pollingContext({above:false}); assert.equal(below.replacements,1); assert.equal(below.scrolls.length,0);
  for (const disclosureOpen of [true, false]) {
    const updated = await pollingContext({disclosureOpen});
    assert.equal(updated.replacements, 1);
    assert.equal(updated.nextDisclosure.open, disclosureOpen);
  }
  const hidden = await pollingContext({visible:false}); assert.equal(hidden.fetches,0); assert.equal(hidden.replacements,0);
  const error = await pollingContext({fail:true}); assert.equal(error.replacements,0); assert.equal(error.scrolls.length,0);
  console.log('Dashboard scroll and live-progress behavior passed.');
})().catch(error => {console.error(error); process.exitCode=1;});
