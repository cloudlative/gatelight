'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const css = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.css'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
const js = ['app.js', 'traffic.js', 'forge.js'].map((f) => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8')).join('\n');

test('an inactive page is never displayed: only "#view-x.active" may show a page', () => {
  // `#view-x { display: flex }` would beat `.view { display: none }` and leave the page on screen under every other page
  for (const m of css.matchAll(/(^|\n)(#view-[\w-]+)(?:\s*,\s*#view-[\w-]+)*\s*\{([^}]*)\}/g)) {
    const sel = m[0].split('{')[0]; if (/\.active/.test(sel)) continue;
    assert.ok(!/display\s*:\s*(flex|grid|block)\b/.test(m[3]), `${sel.trim()} sets display without .active`);
  }
});

test('every page has a section, and every nav entry points at one', () => {
  const sections = new Set([...html.matchAll(/<section class="view[^"]*" id="view-([\w-]+)"/g)].map((m) => m[1]));
  for (const m of html.matchAll(/<button[^>]*data-view="([\w-]+)"/g)) assert.ok(sections.has(m[1]) || m[1] === 'connect', `nav entry ${m[1]} has no page`);
  for (const id of ['urlmap', 'infra', 'tree', 'graph-wrap']) assert.ok(html.includes(`id="${id}"`), `#${id} is missing`);
});

test('features that were merged keep their controls', () => {
  assert.match(js, /\['diagram', 'Diagram'\]/); assert.match(js, /function renderUrlMap/); assert.match(js, /data-fg-export/); assert.match(js, /Official documentation/);
});

test('every page with filters clears them when you leave it', () => {
  const block = /const FILTER_RESETS = \{([\s\S]*?)\n\};/.exec(js);
  assert.ok(block, 'FILTER_RESETS is missing');
  for (const v of ['topology', 'services', 'graphs', 'config', 'events', 'forge', 'traffic', 'flow']) assert.ok(new RegExp(`\\n  ${v}\\(\\)`).test(block[1]), `${v} does not reset its filters`);
  assert.match(block[1], /state\.sort = \{ key: 'default'/, 'the Services sort order is reset');
  assert.match(block[1], /FG\.kind = 'all'/, 'Config Forge filters are reset');
});
