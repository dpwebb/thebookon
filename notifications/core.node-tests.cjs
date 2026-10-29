'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { createNotifications } = require('./core.cjs');
const fixtures = [];
function fixture(overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'native-notification-'));
  const env = { NODE_ENV: 'test', NOTIFICATIONS_MODE: 'capture', NOTIFICATIONS_DIRECTORY: directory, NOTIFICATIONS_ENCRYPTION_KEY: 'ab'.repeat(32), ...overrides.env };
  let time = 1000000000;
  const options = { project: 'test', name: 'Test', from: 'admin@example.test', origin: 'https://example.test', env, now: () => time,
    templates: { 'test.customer': { audience: 'customer', subject: 'Receipt', path: '/account', text: i => 'Reference: ' + i.reference },
      'test.operator': { audience: 'operator', subject: 'Operator notice', path: '/admin', text: i => 'Reference: ' + i.reference } }, ...overrides };
  options.env = env;
  const f = { directory, options, tick: ms => { time += ms; } }; fixtures.push(f);
  f.queue = createNotifications(options); return f;
}
const notice = (key = 'event-1') => ({ event: 'test.customer', key, reference: 'record-1', to: 'customer@example.test' });
test.afterEach(async () => { for (const f of fixtures.splice(0)) { await f.queue?.close(); assert.ok(path.resolve(f.directory).startsWith(path.resolve(os.tmpdir()) + path.sep + 'native-notification-')); fs.rmSync(f.directory, { recursive: true, force: true }); } });
test('disabled mode never opens storage or calls transport', async () => {
  const f = fixture({ env: { NOTIFICATIONS_MODE: 'disabled', NOTIFICATIONS_DIRECTORY: undefined, NOTIFICATIONS_ENCRYPTION_KEY: undefined }, send: () => { throw Error('must not send'); } });
  assert.equal((await f.queue.enqueue(notice())).status, 'disabled'); assert.equal((await f.queue.dispatch()).status, 'disabled'); assert.deepEqual(fs.readdirSync(f.directory), []);
});
test('one event produces one persisted encrypted receipt from its project admin', async () => {
  const f = fixture(); const first = await f.queue.enqueue(notice());
  assert.equal((await f.queue.enqueue(notice())).duplicate, true);
  assert.equal((await f.queue.dispatch()).status, 'captured'); assert.equal((await f.queue.dispatch()).status, 'idle');
  const captures = f.queue.captures(); assert.equal(captures.length, 1); assert.equal(captures[0].from, 'admin@example.test'); assert.equal(captures[0].to, 'customer@example.test');
  const bytes = fs.readFileSync(path.join(f.directory, 'notification-outbox.sqlite'));
  assert.equal(bytes.includes(Buffer.from('customer@example.test')), false); assert.equal(bytes.includes(Buffer.from('Reference: record-1')), false); assert.ok(first.id);
});
test('idempotency keys cannot be reused for another recipient', async () => {
  const f = fixture(); await f.queue.enqueue(notice()); await assert.rejects(f.queue.enqueue({ ...notice(), to: 'other@example.test' }), /IDEMPOTENCY_CONFLICT/);
});
test('rejects header injection, unknown events and invalid source references', async () => {
  const f = fixture(); await assert.rejects(f.queue.enqueue({ ...notice(), to: 'x@example.test\r\nBcc: private@example.test' }), /RECIPIENT_INVALID/);
  await assert.rejects(f.queue.enqueue({ ...notice(), event: 'toString' }), /EVENT_INVALID/);
  await assert.rejects(f.queue.enqueue({ ...notice(), reference: 'private\nmessage' }), /EVENT_INVALID/);
});
test('operator notices cannot be redirected by request input', async () => {
  const f = fixture(); await assert.rejects(f.queue.enqueue({ ...notice(), event: 'test.operator' }), /RECIPIENT_INVALID/);
  await f.queue.enqueue({ event: 'test.operator', key: 'operator-1', reference: 'record-1' }); await f.queue.dispatch(); assert.equal(f.queue.captures()[0].to, 'admin@example.test');
});
test('production capture, other project senders and missing encryption fail closed', () => {
  assert.throws(() => fixture({ env: { NODE_ENV: 'production' } }), /CAPTURE_IS_LOCAL_ONLY/);
  assert.throws(() => fixture({ env: { MAIL_FROM: 'admin@other.test' } }), /SENDER_MISMATCH/);
  assert.throws(() => fixture({ env: { NOTIFICATIONS_ENCRYPTION_KEY: '' } }), /PRIVATE_STORAGE_REQUIRED/);
});
test('reopening an outbox retains deduplication and prior acceptance', async () => {
  const f = fixture(); await f.queue.enqueue(notice()); await f.queue.close(); f.queue = createNotifications(f.options);
  await f.queue.dispatch(); assert.equal((await f.queue.enqueue(notice())).duplicate, true); assert.equal(f.queue.captures().length, 1);
});
test('known temporary SMTP rejection retries with backoff; acceptance stops retries', async () => {
  let sends = 0; const f = fixture({ env: { NOTIFICATIONS_MODE: 'smtp' }, send: async mail => { if (++sends === 1) throw Object.assign(Error('temporary'), { responseCode: 451 }); return { accepted: [mail.to], rejected: [] }; } });
  await f.queue.enqueue(notice()); assert.equal((await f.queue.dispatch()).status, 'retry'); assert.equal((await f.queue.dispatch()).status, 'idle'); f.tick(60000);
  assert.equal((await f.queue.dispatch()).status, 'accepted'); assert.equal((await f.queue.dispatch()).status, 'idle'); assert.equal(sends, 2);
});
test('permanent rejection and ambiguous SMTP outcomes are not replayed', async () => {
  for (const responseCode of [550, undefined]) {
    let sends = 0; const f = fixture({ env: { NOTIFICATIONS_MODE: 'smtp' }, send: async () => { sends++; throw Object.assign(Error('SMTP failed'), { responseCode }); } });
    await f.queue.enqueue(notice()); assert.equal((await f.queue.dispatch()).status, responseCode ? 'failed' : 'unknown'); f.tick(3600000); assert.equal((await f.queue.dispatch()).status, 'idle'); assert.equal(sends, 1);
  }
});
test('expired sending leases become unknown without a duplicate send', async () => {
  let sends = 0; const f = fixture({ env: { NOTIFICATIONS_MODE: 'smtp' }, send: async mail => { sends++; return { accepted: [mail.to] }; } });
  const job = await f.queue.enqueue(notice()); const db = new DatabaseSync(path.join(f.directory, 'notification-outbox.sqlite'));
  db.prepare("UPDATE notifications SET status='sending',lease_until=1 WHERE id=?").run(job.id); db.close();
  assert.equal((await f.queue.dispatch()).status, 'idle'); assert.equal(sends, 0); assert.equal(f.queue.health().statuses[0].status, 'unknown');
});
test('rate limiting defers pending notices rather than discarding them', async () => {
  const f = fixture({ env: { NOTIFICATIONS_RECIPIENT_HOURLY_LIMIT: '1' } });
  await f.queue.enqueue(notice('one')); await f.queue.enqueue(notice('two'));
  await f.queue.dispatch(); assert.equal((await f.queue.dispatch()).status, 'rate_limited'); assert.equal(f.queue.captures().length, 1);
  f.tick(3600001); assert.equal((await f.queue.dispatch()).status, 'captured'); assert.equal(f.queue.captures().length, 2);
});
test('revoked source events are cancelled and tampered payloads are never sent', async () => {
  const f = fixture({ eligible: async () => false }); await f.queue.enqueue(notice()); assert.equal((await f.queue.dispatch()).status, 'cancelled');
  const g = fixture(); const job = await g.queue.enqueue(notice()); const db = new DatabaseSync(path.join(g.directory, 'notification-outbox.sqlite'));
  db.prepare("UPDATE notifications SET payload='{}' WHERE id=?").run(job.id); db.close(); assert.equal((await g.queue.dispatch()).status, 'failed'); assert.deepEqual(g.queue.captures(), []);
});
test('notification storage failure does not falsely report queued or undo business success', async () => {
  const f = fixture(); fs.writeFileSync(path.join(f.directory, 'not-a-folder'), 'x');
  await f.queue.close(); f.options.env.NOTIFICATIONS_DIRECTORY = path.join(f.directory, 'not-a-folder', 'queue'); f.queue = createNotifications(f.options);
  assert.equal((await f.queue.notify(notice())).status, 'unavailable');
});
test('two workers claim a notification only once', async () => {
  let sends = 0; const f = fixture({ env: { NOTIFICATIONS_MODE: 'smtp' }, send: async mail => { sends++; await new Promise(r => setTimeout(r, 20)); return { accepted: [mail.to] }; } });
  const second = createNotifications(f.options); await f.queue.enqueue(notice());
  await Promise.all([f.queue.dispatch(), second.dispatch()]); await second.close(); assert.equal(sends, 1);
});
test('temporary eligibility lookup failure retries before any message is sent', async () => {
  let sends = 0; const f = fixture({ env: { NOTIFICATIONS_MODE: 'smtp' }, eligible: async () => { throw Error('DB offline'); }, send: async mail => { sends++; return { accepted: [mail.to] }; } });
  await f.queue.enqueue(notice()); assert.equal((await f.queue.dispatch()).status, 'retry'); assert.equal(sends, 0);
});

test('five explicit temporary rejections exhaust the retry budget as a known failure', async () => {
  let sends=0;
  const f=fixture({env:{NOTIFICATIONS_MODE:'smtp'},send:async()=>{sends++;throw Object.assign(Error('temporary rejection'),{responseCode:451});}});
  await f.queue.enqueue(notice());
  for(let attempt=0;attempt<5;attempt++){const result=await f.queue.dispatch();assert.equal(result.status,attempt===4?'failed':'retry');f.tick(1800001);}
  assert.equal(sends,5);assert.equal((await f.queue.dispatch()).status,'idle');
});
test('expired receipts lose their encrypted content but retain deduplication tombstones', async () => {
  const f = fixture(); await f.queue.enqueue(notice()); await f.queue.dispatch(); f.tick(8 * 86400000); await f.queue.dispatch();
  assert.deepEqual(f.queue.captures(), []); assert.equal((await f.queue.enqueue(notice())).duplicate, true);
});
test('another project cannot consume or modify this project outbox', async () => {
  const f = fixture(); await f.queue.enqueue(notice());
  const foreign = createNotifications({ ...f.options, project: 'other-project', from: 'admin@other.test' });
  await assert.rejects(foreign.dispatch(), /PROJECT_STORAGE_MISMATCH/); await foreign.close();
  assert.equal((await f.queue.dispatch()).status, 'captured'); assert.equal(f.queue.captures()[0].from, 'admin@example.test');
});
