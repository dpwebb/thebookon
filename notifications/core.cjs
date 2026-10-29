'use strict';
// Server-only notification outbox. Business records remain the source of truth.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const email = value => typeof value === 'string' && value.length <= 254 && /^[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+$/.test(value);
const cleanReference = value => typeof value === 'string' && /^[A-Za-z0-9_.:/-]{1,160}$/.test(value);

function createNotifications(options) {
  const env = options.env || process.env;
  const mode = env.NOTIFICATIONS_MODE || 'disabled';
  const now = options.now || Date.now;
  const from = options.from.toLowerCase();
  const operator = (env.NOTIFICATIONS_OPERATOR_TO || from).toLowerCase();
  if (!['disabled', 'capture', 'smtp'].includes(mode)) throw Error('NOTIFICATIONS_MODE_INVALID');
  if (!email(from) || !email(operator)) throw Error('NOTIFICATIONS_ADDRESS_INVALID');
  if (mode !== 'disabled' && env.MAIL_FROM && env.MAIL_FROM.toLowerCase() !== from) throw Error('NOTIFICATIONS_SENDER_MISMATCH');
  if (env.NODE_ENV === 'production' && mode === 'capture') throw Error('NOTIFICATIONS_CAPTURE_IS_LOCAL_ONLY');
  let db, timer, working, lastIssue = null;
  const origin = new URL(mode === 'disabled' ? options.origin : env.APP_ORIGIN || options.origin);
  if (origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash ||
      !(origin.protocol === 'https:' || mode !== 'smtp' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname))) throw Error('NOTIFICATIONS_ORIGIN_INVALID');
  const configuredKey = env.NOTIFICATIONS_ENCRYPTION_KEY;
  const directory = env.NOTIFICATIONS_DIRECTORY;
  if (mode !== 'disabled' && (!directory || !path.isAbsolute(directory) || !/^[a-f0-9]{64}$/i.test(configuredKey || ''))) throw Error('NOTIFICATIONS_PRIVATE_STORAGE_REQUIRED');
  const key = mode !== 'disabled' ? Buffer.from(configuredKey, 'hex') : null;
  const limit = (name, fallback, maximum) => {
    const value = Number(env[name] || fallback);
    if (!Number.isInteger(value) || value < 1 || value > maximum) throw Error('NOTIFICATIONS_LIMIT_INVALID');
    return value;
  };
  const recipientLimit = limit('NOTIFICATIONS_RECIPIENT_HOURLY_LIMIT', 20, 1000);
  const dailyLimit = limit('NOTIFICATIONS_DAILY_LIMIT', 200, 10000);
  function store() {
    if (db) return db;
    const root = path.resolve(directory);
    for (const name of ['public', 'static', 'dist', 'node_modules', '.git']) {
      const denied = path.resolve(name);
      if (root === denied || root.startsWith(denied + path.sep)) throw Error('NOTIFICATIONS_STORAGE_IS_PUBLIC');
    }
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    if (fs.lstatSync(root).isSymbolicLink()) throw Error('NOTIFICATIONS_STORAGE_SYMLINK');
    const actualRoot = fs.realpathSync(root);
    for (const name of ['public', 'static', 'dist', 'node_modules', '.git']) {
      const candidate = path.resolve(name);
      const denied = fs.existsSync(candidate) ? fs.realpathSync(candidate) : candidate;
      if (actualRoot === denied || actualRoot.startsWith(denied + path.sep)) throw Error('NOTIFICATIONS_STORAGE_IS_PUBLIC');
    }
    const filename = path.join(root, 'notification-outbox.sqlite');
    if (fs.existsSync(filename) && fs.lstatSync(filename).isSymbolicLink()) throw Error('NOTIFICATIONS_STORAGE_SYMLINK');
    const connection = new DatabaseSync(filename);
    fs.chmodSync(filename, 0o600);
    try {
      connection.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE;');
      connection.exec('BEGIN IMMEDIATE');
      try {
        const version = connection.prepare('PRAGMA user_version').get().user_version;
        if (version > 1) throw Error('NOTIFICATIONS_SCHEMA_TOO_NEW');
        if (version === 0) {
          connection.exec(fs.readFileSync(path.join(__dirname, 'migrations/001-outbox.sql'), 'utf8'));
          connection.prepare('INSERT INTO notification_meta(name,value) VALUES(?,?)').run('project', options.project);
          connection.exec('PRAGMA user_version=1');
        }
        const project = connection.prepare("SELECT value FROM notification_meta WHERE name='project'").get();
        if (project?.value !== options.project) throw Error('NOTIFICATIONS_PROJECT_STORAGE_MISMATCH');
        connection.exec('COMMIT');
      } catch (error) { connection.exec('ROLLBACK'); throw error; }
      db = connection;
    } catch (error) { connection.close(); throw error; }
    return db;
  }
  function encrypt(value, id) {
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(options.project + ':' + id));
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
  }
  function decrypt(value, id) {
    const data = JSON.parse(value), decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'base64'));
    decipher.setAAD(Buffer.from(options.project + ':' + id));
    decipher.setAuthTag(Buffer.from(data.tag, 'base64'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(data.data, 'base64')), decipher.final()]).toString());
  }
  function transaction(fn) {
    const connection = store(); connection.exec('BEGIN IMMEDIATE');
    try { const result = fn(connection); connection.exec('COMMIT'); return result; }
    catch (error) { connection.exec('ROLLBACK'); throw error; }
  }
  async function enqueue(input) {
    if (mode === 'disabled') return { status: 'disabled' };
    const template = options.templates[input.event];
    if (!Object.hasOwn(options.templates, input.event) || !template || !cleanReference(input.reference) || !cleanReference(input.key)) throw Error('NOTIFICATION_EVENT_INVALID');
    const to = template.audience === 'customer' ? String(input.to || '').toLowerCase() : operator;
    if (!email(to) || template.audience !== 'customer' && input.to && input.to.toLowerCase() !== operator) throw Error('NOTIFICATION_RECIPIENT_INVALID');
    if (input.code && (!template.code || !/^[a-f0-9]{64}$/i.test(input.code))) throw Error('NOTIFICATION_CODE_INVALID');
    const subject = template.subject;
    if (!subject || /[\r\n]/.test(subject)) throw Error('NOTIFICATION_SUBJECT_INVALID');
    const text = template.text(input) + '\n\nOpen ' + origin.origin + template.path + '\n\n' + options.name;
    const id = hash(options.project + ':' + input.event + ':' + input.key);
    const payload = { from, to, subject, text, event: input.event, reference: input.reference, code: input.code };
    const fingerprint = hash(JSON.stringify(payload));
    return transaction(connection => {
      const previous = connection.prepare('SELECT fingerprint,status FROM notifications WHERE id=?').get(id);
      if (previous) {
        if (previous.fingerprint !== fingerprint) throw Error('NOTIFICATION_IDEMPOTENCY_CONFLICT');
        return { id, status: previous.status, duplicate: true };
      }
      const timestamp = now(), recipientHash = hash(to);
      const pending = connection.prepare("SELECT count(*) AS n FROM notifications WHERE status IN ('queued','retry','sending')").get().n;
      if (pending >= 1000) throw Error('NOTIFICATION_QUEUE_FULL');
      connection.prepare('INSERT INTO notifications(id,event,fingerprint,recipient_hash,payload,status,created_at,due_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)')
        .run(id, input.event, fingerprint, recipientHash, encrypt(payload, id), 'queued', timestamp, timestamp, timestamp + 86400000);
      return { id, status: 'queued', duplicate: false };
    });
  }
  // A notification failure must not undo an already committed business action.
  async function notify(input) {
    try { return await enqueue(input); }
    catch (error) {
      lastIssue = /^[A-Z_]+$/.test(error.message) ? error.message : 'NOTIFICATION_STORAGE_UNAVAILABLE';
      console.warn(JSON.stringify({ component: 'notifications', project: options.project, issue: lastIssue }));
      return { status: 'unavailable' };
    }
  }
  async function performDispatch() {
    if (mode === 'disabled') return { status: 'disabled' };
    const timestamp = now();
    const job = transaction(connection => {
      connection.prepare("UPDATE notifications SET payload='',captured=NULL WHERE status NOT IN ('queued','retry','sending') AND created_at<?").run(timestamp - 7 * 86400000);
      // A crash after DATA acceptance is ambiguous. Never replay an expired lease.
      connection.prepare("UPDATE notifications SET status='unknown',issue='delivery_outcome_unknown',lease_until=0 WHERE status='sending' AND lease_until<=?").run(timestamp);
      connection.prepare("UPDATE notifications SET status='expired',issue='notification_expired' WHERE status IN ('queued','retry') AND expires_at<=?").run(timestamp);
      const row = connection.prepare("SELECT * FROM notifications WHERE status IN ('queued','retry') AND due_at<=? ORDER BY created_at,id LIMIT 1").get(timestamp);
      if (!row) return null;
      const hourly = connection.prepare("SELECT count(*) AS n FROM notifications WHERE recipient_hash=? AND ((status IN ('accepted','captured') AND finished_at>?) OR (status='sending' AND lease_until>?))").get(row.recipient_hash, timestamp - 3600000, timestamp).n;
      const daily = connection.prepare("SELECT count(*) AS n FROM notifications WHERE (status IN ('accepted','captured') AND finished_at>?) OR (status='sending' AND lease_until>?)").get(timestamp - 86400000, timestamp).n;
      if (hourly >= recipientLimit || daily >= dailyLimit) {
        connection.prepare('UPDATE notifications SET due_at=? WHERE id=?').run(timestamp + 60000, row.id);
        return { rateLimited: true };
      }
      connection.prepare("UPDATE notifications SET status='sending',attempts=attempts+1,lease_until=? WHERE id=?").run(timestamp + 60000, row.id);
      return row;
    });
    if (!job) return { status: 'idle' };
    if (job.rateLimited) return { status: 'rate_limited' };
    let payload;
    try { payload = decrypt(job.payload, job.id); }
    catch { store().prepare("UPDATE notifications SET status='failed',issue='payload_integrity_failed',lease_until=0 WHERE id=?").run(job.id); return { status: 'failed' }; }
    const finish = (status, issue = null, due = timestamp) => {
      store().prepare('UPDATE notifications SET status=?,issue=?,due_at=?,lease_until=0,finished_at=? WHERE id=?').run(status, issue, due, ['accepted','captured'].includes(status) ? timestamp : 0, job.id);
      return { id: job.id, status };
    };
    if (options.eligible) {
      try { if (!await options.eligible(payload)) return finish('cancelled', 'source_event_no_longer_eligible'); }
      catch { return finish(job.attempts + 1 >= 5 ? 'failed' : 'retry', 'source_eligibility_unavailable', timestamp + 60000); }
    }
    try {
      const mail = { from, to: payload.to, subject: payload.subject, text: payload.text, messageId: '<notification-' + job.id + '@' + from.split('@')[1] + '>' };
      if (mode === 'capture') {
        store().prepare('UPDATE notifications SET captured=? WHERE id=?').run(encrypt(mail, job.id), job.id);
        return finish('captured');
      }
      const send = options.send || (async message => {
        if (!env.PROJECT_MAIL_MODULE || !path.isAbsolute(env.PROJECT_MAIL_MODULE)) throw Error('NOTIFICATION_TRANSPORT_UNAVAILABLE');
        return require(env.PROJECT_MAIL_MODULE).send(message, { ...env, MAIL_FROM: from });
      });
      const result = await send(mail);
      if (!result || !Array.isArray(result.accepted) || result.accepted.length !== 1 || String(result.accepted[0]).toLowerCase() !== payload.to || result.rejected?.length) throw Error('NOTIFICATION_ACCEPTANCE_UNKNOWN');
      return finish('accepted'); // SMTP acceptance only, never final inbox placement.
    } catch (error) {
      const code = Number(error.responseCode);
      if (code >= 400 && code < 500 && job.attempts + 1 < 5) return finish('retry', 'smtp_temporary_rejection', timestamp + Math.min(1800000, 60000 * 2 ** job.attempts));
      if (code >= 400 && code < 500) return finish('failed', 'smtp_retry_exhausted');
      if (code >= 500 && code < 600) return finish('failed', 'smtp_permanent_rejection');
      return finish('unknown', 'delivery_outcome_unknown');
    }
  }
  function dispatch() {
    if (!working) working = performDispatch().finally(() => { working = null; });
    return working;
  }
  function start() {
    if (mode === 'disabled' || timer) return;
    store();
    timer = setInterval(() => { dispatch().catch(() => { lastIssue = 'NOTIFICATION_WORKER_UNAVAILABLE'; }); }, mode === 'capture' ? 250 : 5000);
    timer.unref();
  }
  function health() {
    return { mode, from, lastIssue, statuses: mode !== 'disabled' ? store().prepare('SELECT status,count(*) AS count FROM notifications GROUP BY status').all() : [] };
  }
  function captures() {
    if (mode !== 'capture') throw Error('CAPTURE_IS_LOCAL_ONLY');
    return store().prepare("SELECT id,captured FROM notifications WHERE status='captured' AND captured IS NOT NULL").all().map(row => decrypt(row.captured, row.id));
  }
  async function close() { if (timer) clearInterval(timer); timer = null; if (working) await working; if (db) db.close(); db = null; }
  function setEligibility(eligible) { if (typeof eligible !== 'function') throw Error('NOTIFICATION_ELIGIBILITY_INVALID'); options.eligible = eligible; }
  return { mode, enqueue, notify, dispatch, start, health, captures, close, setEligibility };
}
module.exports = { createNotifications };
