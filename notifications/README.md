# The Book On native notifications

This branch adds notifications tied to committed application events, sent from `admin@thebookon.ca`. Existing addresses and application permissions are preserved.

Events: author.registered, contact.received, manuscript.received, intake.contact, intake.manuscript, account.reset_help. Operator messages go to the configured operator address, defaulting to this project's own admin inbox. Customer receipts use the recipient derived from the successful application operation, not an arbitrary notification endpoint. No public mail-sending API is added.

## Local verification

Run `node --test notifications/core.node-tests.cjs` from this package. Use `NOTIFICATIONS_MODE=capture`, an absolute private temporary `NOTIFICATIONS_DIRECTORY`, and a fixture-only 64-character hex `NOTIFICATIONS_ENCRYPTION_KEY`. Capture never contacts SMTP and is rejected in production. Run the project's existing typecheck, tests and build as applicable.

## Activation requirements

The default is `NOTIFICATIONS_MODE=disabled`. For an explicitly authorized release set mode `smtp`, a private persistent `NOTIFICATIONS_DIRECTORY`, a unique 32-byte encryption key as 64 hex characters, the existing SMTP account settings, `MAIL_FROM=admin@thebookon.ca`, and the existing absolute `PROJECT_MAIL_MODULE` path. Do not put credentials in Git, browser code, logs, or these instructions. Runtime sender mismatches fail closed. Reuse the previously configured authenticated TLS transport; do not start another mail server.

An in-process dispatcher starts with the server when configured. It persists encrypted payloads and idempotency keys in SQLite, bounds the queue to 1,000 pending notices, defers rate-limited messages, expires unsubmitted messages after 24 hours, and discards terminal message content after seven days while retaining deduplication tombstones. Only explicit temporary SMTP rejection is retried, with backoff and a five-attempt cap. Ambiguous outcomes and expired sending leases require operator review and are never replayed automatically. SMTP acceptance is not proof of inbox placement.

`node notifications/status.cjs` reads mode and aggregate queue state without revealing recipients, message text, tokens, or credentials. The queue is separate from the business transaction: if enqueue storage fails, the committed business action remains successful and a sanitized issue is recorded; source records are retained for manual reconciliation. Do not describe the two stores as one atomic transaction. No historical events are replayed automatically.

## Custody and release boundaries

Worktree: `C:\Compnd.Systems\worktrees\email-notifications-20261028\The-Book-On`. Branch: `codex/native-email-notifications`. This is isolated local implementation, not a canonical repository cutover or production activation. Preserve original checkouts and private configuration. Read `C:\Compnd.Systems\governance\LOCAL-REPOSITORIES.csv`, the operating charter and authority matrix in `C:\Users\webbd\.codex\operations\compnd-systems`, and current project holds before publication or deployment. No campaigns, trading, provider activation, or customer mail is authorized solely by this source change.

Runtime requirement: Node.js 24 (the maintained Docker runtime) includes `node:sqlite`. The Book On image is upgraded from Node 20 for this feature. SocialScrapper can use current Node 22.13 or later. Notification files and the SQLite migration must be copied into the server image; never expose this folder through a static route.
