'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function updaterHarness() {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const start = source.indexOf('function openSettingsEditor()');
  const end = source.indexOf('\nfunction openProxyEditor(', start);
  const document = new EventTarget();
  document.hidden = false;
  const window = new EventTarget();
  window.location = { reload() {} };
  const nodes = new Map();
  const timers = new Map();
  const requests = [];
  let editor;
  let nextTimer = 0;
  const context = {
    document, window, AbortController, console,
    state: {}, ui: { version: 'v1.0.0', editorSession: 1 },
    clone: (value) => structuredClone(value),
    escapeHtml: String,
    droppedLogMaxBytesFor: () => 10 * 1024 * 1024,
    droppedLogMaxMBFor: () => 10,
    formatDateTime: String,
    formatBytes: String,
    isAbortError: (error) => error?.name === 'AbortError',
    openEditor: (value) => { editor = value; },
    $: (id) => {
      if (!nodes.has(id)) nodes.set(id, { open: id === 'editorDialog', classList: { toggle() {} }, querySelectorAll: () => [] });
      return nodes.get(id);
    },
    setTimeout: (callback) => { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout: (id) => timers.delete(id),
    api: (url, { signal } = {}) => new Promise((resolve, reject) => {
      requests.push({ url, signal, resolve });
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
    }),
  };
  vm.runInNewContext(`${source.slice(start, end)}; openSettingsEditor();`, context);
  const cleanup = editor.onOpen(1);
  return {
    document, window, timers, requests, cleanup,
    hide() { document.hidden = true; document.dispatchEvent(new Event('visibilitychange')); },
    show() { document.hidden = false; document.dispatchEvent(new Event('visibilitychange')); },
    runTimer() {
      const [id, callback] = timers.entries().next().value;
      timers.delete(id);
      callback();
    },
  };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('hidden settings suspend updater requests and resume without duplicate polling', async () => {
  const h = updaterHarness();
  assert.equal(h.requests.length, 1);
  h.requests[0].resolve({ busy: true, phase: 'downloading', version: 'v1.1.0' });
  await settle();
  assert.equal(h.timers.size, 1);
  h.hide();
  assert.equal(h.timers.size, 0, 'a hidden updater must leave no polling timer');
  h.show();
  assert.equal(h.requests.length, 2);
  h.show();
  assert.equal(h.requests.length, 2, 'visibility resumes share the in-flight request');
  h.requests[1].resolve({ busy: true, phase: 'downloading', version: 'v1.1.0' });
  await settle();
  h.runTimer();
  assert.equal(h.requests.length, 3);
  h.hide();
  assert.equal(h.requests[2].signal.aborted, true, 'hide cancels the in-flight status read');
  await settle();
  assert.equal(h.timers.size, 0);
  h.cleanup();
  h.show();
  assert.equal(h.requests.length, 3, 'closed settings must remove their visibility listener');
});

test('back-forward cache suspension stops updater even before document becomes hidden', async () => {
  const h = updaterHarness();
  h.window.dispatchEvent(new Event('pagehide'));
  assert.equal(h.requests[0].signal.aborted, true);
  await settle();
  h.show();
  assert.equal(h.requests.length, 1, 'visibility alone cannot restart a suspended page');
  h.window.dispatchEvent(new Event('pageshow'));
  assert.equal(h.requests.length, 2);
  h.requests[1].resolve({ busy: true, phase: 'downloading', version: 'v1.1.0' });
  await settle();
  assert.equal(h.timers.size, 1);
  h.cleanup();
  assert.equal(h.timers.size, 0);
  h.window.dispatchEvent(new Event('pageshow'));
  assert.equal(h.requests.length, 2, 'cleanup must remove the pageshow listener');
});
