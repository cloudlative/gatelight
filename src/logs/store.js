'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Where the aggregates of an uploaded traffic log live: DATA_DIR/logs/<instance>.json (mode 0600).
 * Only the aggregates are stored, never the raw log. They do contain client IP addresses and URL paths, so the folder is private.
 */
class LogStore {
  constructor(dataDir) { this.dir = path.join(dataDir, 'logs'); }
  file(id) { return path.join(this.dir, `${String(id).replace(/[^\w.-]/g, '_')}.json`); }
  save(id, result) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const f = this.file(id); const tmp = `${f}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(result), { mode: 0o600 });
    fs.renameSync(tmp, f);
  }
  /** The stored JSON text (served as is), or null. */
  raw(id) { try { return fs.readFileSync(this.file(id), 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
  meta(id) {
    const r = this.raw(id); if (r === null) return null;
    const j = JSON.parse(r);
    return { generated: j.generated, source: j.source, range: j.range, stats: j.stats, bucketMs: j.bucketMs };
  }
  has(id) { return fs.existsSync(this.file(id)); }
  remove(id) { try { fs.unlinkSync(this.file(id)); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
}

module.exports = { LogStore };
