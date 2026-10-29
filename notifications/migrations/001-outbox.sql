CREATE TABLE notifications (
  id TEXT NOT NULL PRIMARY KEY,
  event TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  recipient_hash TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','sending','retry','captured','accepted','failed','unknown','cancelled','expired')),
  created_at INTEGER NOT NULL,
  due_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER NOT NULL DEFAULT 0,
  issue TEXT,
  captured TEXT,
  finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX notifications_due ON notifications(status,due_at);
CREATE INDEX notifications_rate ON notifications(recipient_hash,created_at);
CREATE TABLE notification_meta(name TEXT NOT NULL PRIMARY KEY,value TEXT NOT NULL);
