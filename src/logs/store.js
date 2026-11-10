'use strict';
const fs = require('fs');
const path = require('path');
const { mergeResults } = require('./merge');

const MAX_PARTS = 20;

/**
 * Where the aggregates of uploaded traffic logs live (never the raw logs). They do contain client IP addresses and URL
 * paths, so everything is private (0700 folders, 0600 files):
 *   DATA_DIR/logs/<instance>.parts/<part>.json   one per uploaded file
 *   DATA_DIR/logs/<instance>.json                the combined result of all parts (what the dashboard reads)
 */
class LogStore {
  constructor(dataDir) { this.dir = path.join(dataDir, 'logs'); }
  safe(id) { return String(id).replace(/[^\w.-]/g, '_'); }
  file(id) { return path.join(this.dir, `${this.safe(id)}.json`); }
  partsDir(id) { return path.join(this.dir, `${this.safe(id)}.parts`); }
  write(f, text) { const tmp = `${f}.${process.pid}.tmp`; fs.writeFileSync(tmp, text, { mode: 0o600 }); fs.renameSync(tmp, f); }
  partIds(id) { try { return fs.readdirSync(this.partsDir(id)).filter((n) => n.endsWith('.json')).map((n) => n.slice(0, -5)).sort(); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } }
  readPart(id, pid) { return JSON.parse(fs.readFileSync(path.join(this.partsDir(id), `${pid}.json`), 'utf8')); }
  /** An older single-file upload has no parts folder: adopt it as the first part. */
  adopt(id) {
    if (this.partIds(id).length || !this.has(id)) return;
    const raw = this.raw(id); const j = JSON.parse(raw); j.source = { ...j.source, part: 'p000' };
    fs.mkdirSync(this.partsDir(id), { recursive: true, mode: 0o700 }); this.write(path.join(this.partsDir(id), 'p000.json'), JSON.stringify(j));
  }
  rebuild(id) {
    const ids = this.partIds(id);
    if (!ids.length) { try { fs.unlinkSync(this.file(id)); } catch (e) { if (e.code !== 'ENOENT') throw e; } try { fs.rmdirSync(this.partsDir(id)); } catch { /* already gone */ } return null; }
    const parts = ids.map((p) => { const j = this.readPart(id, p); j.source = { ...j.source, part: p }; return j; });
    const files = parts.map((p) => ({ part: p.source.part, filename: p.source.filename, bytes: p.source.bytes, lines: p.source.lines, gzip: Boolean(p.source.gzip), range: p.range, generated: p.generated, demo: undefined }));
    const total = files.reduce((a, f) => ({ bytes: a.bytes + (f.bytes || 0), lines: a.lines + (f.lines || 0) }), { bytes: 0, lines: 0 });
    const source = { filename: files.length === 1 ? files[0].filename : `${files.length} files`, bytes: total.bytes, lines: total.lines, gzip: files.length === 1 && files[0].gzip, files };
    const out = mergeResults(parts, { source });
    this.write(this.file(id), JSON.stringify(out));
    return out;
  }
  /** Add one uploaded file's aggregates. `replace` drops the earlier files first. Throws {code} for duplicates / too many files. */
  add(id, result, { replace = false } = {}) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (replace) this.clearParts(id); else this.adopt(id);
    const ids = this.partIds(id);
    const s = result.source || {};
    if (!replace) {
      if (ids.length >= MAX_PARTS) { const e = new Error(`At most ${MAX_PARTS} files can be combined. Delete some first, or upload a bigger log instead.`); e.code = 'TOO_MANY'; e.status = 409; throw e; }
      for (const p of ids) { const prev = this.readPart(id, p); if (prev.product && result.product && prev.product !== result.product) { const e = new Error(`This is ${result.product === 'nginx' ? 'an NGINX' : 'an HAProxy'} log, but the files already uploaded are ${prev.product === 'nginx' ? 'NGINX' : 'HAProxy'} logs. Use one kind per instance, or delete the existing files first.`); e.code = 'TOO_MANY'; e.status = 409; throw e; } break; }
      for (const p of ids) { const o = this.readPart(id, p).source || {}; if (o.filename === s.filename && o.bytes === s.bytes && o.lines === s.lines) { const e = new Error(`“${s.filename}” is already included (same name, size and line count).`); e.code = 'DUPLICATE'; e.status = 409; throw e; } }
    }
    const pid = `p${String((ids.length ? Number(ids[ids.length - 1].slice(1)) + 1 : 0)).padStart(3, '0')}`;
    fs.mkdirSync(this.partsDir(id), { recursive: true, mode: 0o700 });
    this.write(path.join(this.partsDir(id), `${pid}.json`), JSON.stringify(result));
    try { return { part: pid, combined: this.rebuild(id) }; } catch (e) { try { fs.unlinkSync(path.join(this.partsDir(id), `${pid}.json`)); } catch { /* ignore */ } throw e; }
  }
  /** Replace everything with this one result (kept for single-file callers). */
  save(id, result) { return this.add(id, result, { replace: true }); }
  removePart(id, pid) {
    this.adopt(id);
    const f = path.join(this.partsDir(id), `${String(pid).replace(/[^\w-]/g, '')}.json`);
    try { fs.unlinkSync(f); } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
    this.rebuild(id); return true;
  }
  clearParts(id) { fs.rmSync(this.partsDir(id), { recursive: true, force: true }); }
  /** The stored JSON text (served as is), or null. */
  raw(id) { try { return fs.readFileSync(this.file(id), 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
  meta(id) {
    const r = this.raw(id); if (r === null) return null;
    const j = JSON.parse(r);
    return { generated: j.generated, source: j.source, range: j.range, stats: j.stats, bucketMs: j.bucketMs };
  }
  has(id) { return fs.existsSync(this.file(id)); }
  remove(id) { const had = this.has(id); this.clearParts(id); try { fs.unlinkSync(this.file(id)); } catch (e) { if (e.code !== 'ENOENT') throw e; } return had; }
}

module.exports = { LogStore, MAX_PARTS };
