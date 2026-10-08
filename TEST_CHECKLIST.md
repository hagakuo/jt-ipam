# jt-ipam Release Test Checklist

> zh-TW version: [TEST_CHECKLIST_zh-TW.md](TEST_CHECKLIST_zh-TW.md).

> Rule: **before bumping the `version` in `frontend/package.json`, run this whole
> checklist once; only release when everything is green.**
> Treat it as the manual gate. Fix the red ones first; do not ship sick.

Release flow: run the checklist → all green → bump version → deploy
(backend rsync + alembic + restart; frontend build).

---

## 1. Static checks (dev box, no DB, fastest)

- [ ] Backend imports: `cd backend && set -a; source <env>; set +a; .venv/bin/python -c "import app.main"`
- [ ] Backend pytest collection has no error (DB tests skip): `.venv/bin/pytest -q`
- [ ] Frontend types: `cd frontend && npx vue-tsc --noEmit` (must be zero errors)
- [ ] Frontend build: `npm run build` (dist produced successfully)
- [ ] i18n: every new key exists in both `zh-TW.json` and `en-US.json`; no hard-coded
  Chinese slipped through
- [ ] **Dependency audits with exactly the CI commands**: `cd frontend && pnpm audit --audit-level moderate` (dev
  dependencies included; running only `--prod` misses what CI's audit job checks, which is how v0.6.61 went out and turned
  red) and `cd backend && .venv/bin/pip-audit`. Only a dev-only advisory with no patched version may be listed in
  `frontend/package.json` `pnpm.auditConfig.ignoreGhsas`, with the reason in the commit message; if a patch exists, upgrade

## 2. Database / migration (use a throwaway test DB, never touch prod data)

- [ ] A fresh DB upgrades from 0001 to head cleanly: run `alembic upgrade head`
  against `jt_ipam_test`
- [ ] Each new migration has a `downgrade()` and survives one
  `alembic downgrade -1` then `upgrade head` round-trip
- [ ] No "model changed but migration forgotten": after upgrading to head the app
  starts without an asyncpg "column does not exist" error
- [ ] **Constraint changes**: when a migration drops or adds a UNIQUE constraint, audit
  every query that relied on it. `scalar_one_or_none()` on a column that can now repeat
  becomes a 500 the moment a second row appears (v0.5.194: `users.email`), and code that
  wrote the column unconditionally starts hitting IntegrityError

## 3. Backend integration tests (test DB + pytest, thorough)

- [ ] With `JTIPAM_TEST_DATABASE_URL` set, `.venv/bin/pytest -q` is all green
  (e2e CRUD / auth / each module)
- [ ] Auth: login, refresh, TOTP, permissions (unauthorized `require_admin`
  endpoints return 401/403)
- [ ] Core CRUD: sections / subnets / addresses / devices / customers / locations / racks
- [ ] Audit chain: write operations are audited and chain integrity verifies

## 3c. Failures that come from the data, not the code: **whenever a read schema, an integration writer, or a recurring producer changes**

Three defects in one release (0.6.9) shared a shape the plan above does not catch: **the code is
correct, the data is legitimate, and the page still breaks, with nothing on screen saying why.**
None of them would have been found by "does the endpoint return 200 on a clean database".

### Read schemas must not be stricter than the database

A customer saw the dashboard count 55 devices while the device list returned Internal Server Error
and showed nothing. `DeviceRead` inherited the write-side limits (`vendor`/`model` ≤ 64 chars,
`u_position` 1–99) but those columns are `text` and an unconstrained `integer`, so an integration
wrote a value the database accepts and the read path rejects, and **one row killed the whole page**.

- [ ] For every read schema touched this release, compare each constrained field against the real
  column (`\d <table>`): a `max_length` on a `text` column, or a `ge`/`le` on an unconstrained
  `integer`, is a latent 500 waiting for an integration to write a longer value
- [ ] Constraints that the **database** enforces (CHECK, enum, varchar(n)) may stay strict on read:
  those values cannot exist
- [ ] Admin → System check → **data health** must report zero rows. It validates every row with the
  real read schemas, so "green here" means "the list pages can render this database"
- [ ] Diagnostics **data statistics** (`tests/test_doctor_stats.py`, `e2e/system-doctor.spec.ts`): all five groups show
  numbers (no blanks or NaN), adding subnets and IPs changes them on the next check (IPv4 and IPv6 counted apart); a
  non-admin gets 403 from `/api/v1/system/doctor/stats`; the page says it is counted locally and never sent; the
  "Background jobs" time is in the viewer's time zone

> **Diagnostic shortcut worth remembering:** a count that works while the list 500s means the failure
> is *per-row serialization*, not the query; `count(*)` reads no columns, `select(Model)` reads all
> of them. The same asymmetry appears when the schema is behind (a missing column).

### An "ignore" must survive the next run of whatever produced the finding

AI audit findings came back after every run and had to be dismissed again and again, because the
identity was "category + the exact set of cited addresses" and the model cites a different subset
each time.

- [ ] For any dismiss / acknowledge / mute action: dismiss it, **run the producer again**, and
  confirm it does not reappear; pressing the button once is not a test of the button
- [ ] Confirm the opposite too: when genuinely **new** subjects appear, it *does* surface again.
  An "ignore" that also swallows new information is worse than one that does not stick
- [ ] Identity must not depend on model wording, ordering, or the exact subset cited

### If the system can detect it, the system must say it

An interrupted upgrade left the database behind the code. The backend could determine this at
startup; instead every page that reads full records returned 500 and the operator was left guessing.

- [ ] Any condition detectable at startup or during a request (schema drift, missing extension,
  unbuilt frontend, unreachable dependency) is **logged as an error and surfaced in the UI**, not
  left to be inferred from failures
- [ ] The message names the fix, not just the symptom
- [ ] Support questions are a test failure: if diagnosing an issue required asking the customer to
  run SQL or read logs, that diagnosis belongs in Admin → System check instead

## 3b. Authentication realms & account identity

Login spans local / LDAP / RADIUS / OIDC / SAML, and the same human legitimately owns
accounts in more than one of them. Every defect here reaches the user as "I cannot log in",
with the real cause hidden in a traceback.

- [ ] Log in through **every configured realm**; a wrong password returns 401 with a generic
  message (no account enumeration) while the server log records the specific reason
- [ ] **Same person, two realms**: a local account and an LDAP/SSO account sharing one email
  both log in, and neither overwrites the other's row (v0.5.194: the shared email hit the
  UNIQUE index and returned 500 *after* the LDAP bind had already succeeded)
- [ ] **Auto-provisioning**: first external login creates the account, second updates it;
  a collision on any unique column degrades gracefully instead of failing the login
- [ ] Lockout after repeated failures, then unlock; a deactivated account is refused
- [ ] Logging in by email (not username) resolves to exactly one account per realm

## 4. Key API smoke (against prod after deploy, mostly read-only)

- [ ] `GET /api/v1/health` (or `/notifications`) returns 200
- [ ] `GET /api/v1/subnets`, `/addresses`, `/devices`, `/locations`, `/racks` return 200
- [ ] Endpoints touched this release: manually hit one success path + one failure
  path (verify the 4xx is correct)

## 5. OWASP Top 10:2025 self-review (modules touched this release)

- [ ] A01 authorization: do new endpoints correctly use `require_admin` /
  object-level authorization?
- [ ] A03 injection / input validation: Pydantic StrictModel; file uploads verify
  magic bytes + size limit + reject dangerous types (e.g. SVG)
- [ ] A08 integrity: uploads / external data are validated; no path traversal
  (resolved upload/download paths stay inside the allow-listed directory)
- [ ] Secrets: no secret/token written to logs or responses
- [ ] **Outbound guard** (`tests/test_safe_http_guard.py`, `tests/test_netdiag_http_guard.py`): `::ffff:127.0.0.1`,
  `::ffff:169.254.169.254` and `fd00:ec2::254` are refused; a DNS answer that changes to 127.0.0.1 after the check
  is refused at connect time (integrations, shared clients, Tools page HTTP check); a cross-host redirect drops
  credential headers, same-host and http to https keep them; Tools page TCP/UDP/TLS refuse loopback and
  link-local but still test private networks. After deploy: run each integration's Test connection once
  (TLS name check and HTTP/2 must still work through the connect-time guard).
- [ ] **Error text for ordinary accounts** (`tests/test_ai_error_codes.py`): with the LLM unreachable, a non-admin
  sees a translated "Cannot reach the LLM server" in AI chat and IP investigation, no host name; an admin sees the
  reason. A new error code needs `errors.<code>` in all three languages.
- [ ] **New code reported by GitHub code scanning**: check the open alerts after every push; fix or dismiss with a
  written reason (admin-only diagnostics are dismissed as "won't fix").

## 5b. Deploy-script flows (throwaway environment, **never run install on dev/prod**)

Every install problem customers have reported was invisible on an already-working
box, because there the thing is already there: a pre-existing PostgreSQL cluster
on a different major (so `pgvector` got installed for the wrong one), a `pnpm
install` that failed silently and left no frontend, an installer that printed
"Done" while nothing was running, and a backup unit whose `ReadWritePaths`
directory did not exist yet, which systemd reports as `226/NAMESPACE`, an error
that names nothing about the actual cause. **A clean-OS install is the only way
to see what a customer sees.**

- [ ] **Fresh install from a clean OS (required)**: `scripts/test-fresh-install.sh
  debian:12` exits 0. It starts a throwaway systemd container, copies the tree in,
  runs `scripts/jt-ipam.sh install`, then checks the things that only break in the
  field: the backend *answers* on its port, `jt-ipam-backup` and `jt-ipam-sync`
  actually run to `Result=success`, the backup unit survives its directory being
  deleted, and `doctor` agrees with reality
- [ ] Run it for **the oldest supported distro and the newest** (`debian:12`,
  `ubuntu:24.04`); PG-major and Node-version differences live there
- [ ] **Upgrade (required, and separate from the above)**: `scripts/test-upgrade.sh` exits 0.
  Fresh install and upgrade share almost no code, so passing the fresh-install gate says
  nothing about existing sites. Point it at the tree you are about to publish
  (`JT_IPAM_REPO=/path/to/candidate`), not at the last release; otherwise you are testing
  the version you already shipped. It writes a row *before* upgrading and checks it survived:
  losing data is the worst upgrade failure and it does not make any command exit non-zero
- [ ] Against a previous-version environment `scripts/jt-ipam.sh upgrade` also rolls back if needed
- [ ] **Node.js 22 for the frontend build**: both gates check `node -v` in the container against `engines.node`
  (fresh install: v22 and `doctor` shows "Node.js v22... for building the frontend"; upgrade from a release that
  used Node 20, v0.6.61 or older: the log shows Node.js v20 -> v22 and the site still answers over HTTPS). The
  fallback (22 cannot be installed during an upgrade: keep Node 20 or newer, warning banner, `doctor` warns; a
  fresh install stops) and the nvm cases are covered by `scripts/tests/test_ensure_node.sh`
- [ ] If this release added a directory / package / service / DB extension / env,
  confirm **`install` and `upgrade` are both in sync**, and that `doctor` checks it
- [ ] **`scripts/jt-ipam.sh doctor` on prod after deploying**: every line green, or
  the `→ fix` line is one a customer could follow without asking us
- [ ] **(A) Default admin credentials**: fresh install prints the `admin` account +
  random password at the end and saves it to `/etc/jt-ipam/.admin-initial-password`
  (root 0600); that password logs in
- [ ] **(A) Password-reset CLI**: `python -m app.cli.bootstrap create-admin --username
  admin --password-stdin --force-update` resets an existing admin; both READMEs
  document it
- [ ] **(B) Agent probe tools**: after `agent/jt-ipam-agent-installer.sh`, the host has
  `nmap` / `nmblookup` (samba-common-bin) / `avahi-resolve` (avahi-utils); the agent's
  reported `available_probes` includes os/netbios/mdns
- [ ] **(B) Install-help UI**: on the scan-agent page and the subnet edit dialog,
  unavailable probes show an "install help" popover with the matching install command
- [ ] **(C) Reference-data timers**: after a fresh install and after an upgrade, `systemctl list-timers` shows
  `jt-ipam-geoip-refresh`, `jt-ipam-oui-refresh` and `jt-ipam-recog-refresh`; after a fresh install the OUI
  table is not empty (it is fetched once during install); `doctor` lists all three
- [ ] **(C) Recog fingerprint database (optional)**: install / upgrade output shows "Recog: updated …
  fingerprints"; with outbound access blocked an upgrade only warns and still completes;
  `upgrade --recog-zip <recog-content-version.zip>` installs it offline; `python -m app.cli.recog status`
  shows the release
- [ ] **(D) Small machines** (`tests/test_resource_sizing.py`): a fresh install in a `--cpuset-cpus=0,1` or `--memory=4g`
  container runs 2 uvicorn workers (4 cores / 8 GB runs 4; `UVICORN_WORKERS` wins when set); an upgrade in a `--memory=3g`
  container without swap prints "pausing jt-ipam-backend during the frontend build" and the backend is up afterwards; a
  build forced to fail brings the backend back
- [ ] **(D) No zombies after an agent self-update** (`tests/test_agent_reap_inherited.py`): swap the server's agent.py while
  the agent runs an OS probe; within a round or two after the update `ps -eo stat,comm | grep -c '^Z'` is back to 0

## 5c. Real-browser testing: **mandatory for every release that touches the UI**

- [ ] **Run the full e2e with `frontend/e2e/run-release.sh`** (not a hand-rolled `--workers=2` over everything): ordinary
  specs run in parallel, the specs in `e2e/global-state-specs.txt` that change system-wide settings run afterwards one at
  a time; run `seed_e2e` first
- [ ] **Console connection path** (`e2e/console-route-note.spec.ts`, `tests/test_console_route_describe.py`): SSH / SFTP /
  RDP / VNC connect forms show "Connection path: Direct / via jump host "X" / via scan agent "X"" and where it is set (IP
  or subnet); a disabled jump host, an unpinned host key or an agent not allowed to relay shows the reason before
  connecting; "Change" opens a dialog in place (without leaving the connect form) to set this IP's exit, and after
  saving the path line updates (set on the IP); "Change it for the whole subnet" opens the subnet edit dialog; with no
  jump host available and no agent allowed to relay it says only direct is possible and has no Save button; accounts
  that cannot edit do not see "Change"
- [ ] **Jump hosts are a tab on the Scan agents page**: no "Jump hosts" in the sidebar; `/jump-hosts` redirects to
  `/scan-agents?tab=jump`; switching tabs updates the URL

- [ ] Mobile sidebar (`frontend/e2e/mobile-sidebar.spec.ts`, 390×844): collapsed to zero width with the content
  starting at the left edge; the top-left button opens it over the content; picking a page or tapping the
  dimmed area closes it; desktop is unchanged
- [ ] Rack diagrams on phones (`frontend/e2e/mobile-rack.spec.ts`): pan left / right when wider than the
  screen; the Front / Rear toolbar stays inside the card
- [ ] **Every screen at phone width** (`frontend/e2e/mobile-all-routes.spec.ts`, 390px, routes parsed from the
  router): no page-level horizontal scroll, nothing clipped or off screen (unless a horizontally scrollable
  container holds it), no text squeezed to one character per line. With `E2E_SHOT_DIR` it screenshots every
  screen of every page. **Look at them**; the measurements cannot see "ugly but inside the screen"
- [ ] **Column resizing and tab scroll buttons** (site-wide; `e2e/anomaly-identify-cols-tabs.spec.ts`): dragging
  a header edge resizes that column by the distance dragged (hand-written tables too, including headers with
  opacity); **the layout before dragging is exactly as before** (a default minimum width once let tables
  without a fixed layout squeeze IPs into a vertical line on phones; run the phone sweep with it). Arrows
  appear only when the tab bar does not fit and only on the side that has more; the first and last tabs are
  reachable and the arrows never block a tab click
- [ ] **Drag to reorder columns** (every "Columns" picker; `e2e/column-reorder.spec.ts`, vitest
  `columnPickerWiring.test.ts` fails if a picker or a page's columns are not wired): dragging a row by its handle
  moves the table column the same way, also by touch on a phone and with the up and down arrow keys on a focused
  handle; the order survives a reload with the local cache cleared (it comes from `table_columns["<table>:order"]`);
  hiding a column and showing it again puts it back where it was; the selection column, columns fixed left or right
  and columns that are not in the list (actions) do not move; the export uses the displayed order; "Reset to
  default" restores the order. With every column ticked, the list shows the columns in the same order as the table
  header (it did not on Subnets, Locations, NAT and Connections, so the first drag made unrelated columns jump).
  **A table that was never reordered must look exactly as before** (an old saved visible list is in click order and
  must not be read as a column order). Spot-check pages that build columns themselves: Subnet detail (idle-range rows still span from IP
  to the last column), Anomaly categories, Attack surface, and the tabs of Advanced modules, Cabling and power,
  and Virtualization
- [ ] The four phone reports (`frontend/e2e/mobile-overflow.spec.ts`): the sidebar scrolls under a finger and
  does not scroll the page behind; console status bars wrap instead of stacking one character per line; the
  notification popover stays on screen; rack diagrams default to a zoom that fits the phone and remember a
  change (separately from desktop). ⚠️ iOS's 100vh is taller than what is visible and Playwright cannot emulate
  the collapsing toolbar, so **have the sidebar fix confirmed on an iPhone**

Type checks, unit tests and API tests all pass while a page renders the wrong
thing, renders nothing, or puts it in the wrong place. Defects this project has
shipped that were only ever visible in a browser: a column added to a table but
not to the column-picker defaults (so it never appeared), an export that wrote
`undefined` into the report, a date overlapping its buttons, file names that
failed to line up by 16px, and a console that could not connect at all because
the reverse proxy dropped the WebSocket upgrade.

- [ ] `cd frontend && pnpm exec playwright test smoke` (no backend; self-starts
  vite preview) all green
- [ ] **Seed the fixtures first**: `POSTGRES_DB=jt_ipam_e2e python -m tests.seed_e2e`
  (from `backend/`). Several specs assert on specific records, and some of them
  *change* that data as they run -- dismissing an AI finding, for one -- so a second
  run without re-seeding fails on state left by the first. The failure looks exactly
  like a regression, which is how an hour gets spent on nothing
- [ ] Against a deployed instance (`E2E_BASE_URL` + `E2E_ADMIN_PASS`) run the
  **whole** suite: `pnpm test:e2e`. Data-dependent specs need real data, so run those
  against a deployed instance, not an empty test DB
- [ ] **A list page is not proved by opening it.** Compare what the page claims
  (the "共 N 筆" footer) against what the server reports, on a data set larger than
  one page: a page that fetches only the first page and then paginates in the
  browser looks perfectly healthy until someone has more records than that
  (GitHub issue #27: 95 sections, 50 shown, footer saying 50)
- [ ] **Every changed page opened in an actual browser**, console watched: no errors,
  no blank regions, no `undefined` / raw JSON / untranslated i18n keys on screen
- [ ] **A new spec covering what this release changed.** Assert on the effect, not on
  the UI's own claim: read the file back off the remote host, reload the page after
  saving, compare the downloaded bytes. "已上傳" on screen is not evidence
- [ ] **Measure geometry, don't eyeball it**: `boundingBox()` whenever the point is
  alignment, overlap or spacing; a screenshot hides a 16px error
- [ ] **Check narrow widths too.** A layout defect usually only exists below some width, so a
  test that runs at one wide viewport proves nothing: options spilled outside their card at
  820px while every existing test was green (reported by the user, v0.6.2). Any spec that
  asserts layout walks several widths (1500 / 1180 / 900 / 820 / 700), and the route sweep runs
  at 900px asserting no page scrolls horizontally
- [ ] New text checked in both locales (switch to English, confirm no key leaks)
- [ ] **Every route opens**: `playwright test e2e/all-routes.spec.ts` green. It parses the
  route list out of `src/router/index.ts`, so a new page is covered automatically, and it
  fails on blank screens, JS exceptions, failed API calls and untranslated keys. This exists
  because the sweep used to visit 22 of 78 routes: forty-odd pages had never been opened by
  any test. A page that only a human ever opens is a page nothing is checking

## 5g. Messages the server writes on the screen: **whenever an error message is added or changed**

The backend must not send finished sentences. Anything a person reads goes out as
`{code, params, message}` (`app/core/ui_error.py`) and the sentence is assembled from
`errors.<code>` in the browser. A Chinese sentence written into the backend shows up
*as Chinese* in the English and Japanese interfaces, and nothing errors; this shipped
undetected for the entire life of the English translation.

- [ ] `pytest tests/test_ui_error_codes.py`: every code in the source has a translation
  in all three locales (the test walks the source; a missing key is otherwise silent)
- [ ] New codes: read the fallback sentence in each locale and check the parameters are
  actually interpolated. A translation that drops `{reason}` **removes the diagnosis**:
  "pfSense returned an error" without saying whether it was DNS, a refusal or a certificate
- [ ] Switch the UI to English and Japanese and trigger at least one of the new errors for
  real. Codes used for *flow* (not just display) need extra care: the response interceptor
  flattens `detail` to a string, so read the code from `detail_code`; the Proxmox two-factor
  prompt was broken this exact way and nobody noticed
- [ ] No Chinese words passed as parameters (`what="下載"`): put the distinction in the code
  (`sftp_download_too_large`), or the English sentence ends up with a Chinese word in it

## 5h. guacd prebuilt binaries: **every release** (not only when the console changes)

We ship guacd ourselves, one build per operating system version: Debian and Ubuntu no
longer carry a usable package (Debian removed it, Ubuntu only has 1.3.0 with known RCEs).
The builds link against each distribution's own libraries, so **a new OS release needs a
new build**; a customer who upgrades to it otherwise loses the guacd engine. The owner's
instruction (2026-09-25): check online at every release and build for any new version.

- [ ] `scripts/guacd/check-new-os.sh`: asks endoflife.date which Debian (≥12) and Ubuntu
  (≥22.04, interim releases included while supported) versions are in support and compares
  them with `scripts/guacd/targets.txt`. Exit 1 lists what is missing: add it to
  `targets.txt`. Versions past end of support are listed as retirable
- [ ] guacamole-server upstream: new release or CVE since the pinned source in
  `scripts/guacd/source.env`? It is pinned to a `staging/1.6.1` commit because 1.6.0
  segfaults on Ubuntu 26.04 at the first frame; **once 1.6.1 is released, switch to the
  official Apache tarball and verify its published checksum**
- [ ] Walk the installer's guacd path on a clean OS too (guacd is the default RDP / VNC engine, so
  install puts it in by default): `scripts/test-fresh-install.sh debian:12` (the customer path:
  download from the GitHub release and verify) or `GUACD_TARBALL=<prebuilt for the same OS>
  scripts/test-fresh-install.sh debian:12` (a build not published yet); this checks that it installs,
  the service runs, answers on 127.0.0.1 **only**, and doctor is green. guacd is **required**:
  install must stop when it cannot be installed
- [ ] If anything changed: `scripts/guacd/build.sh` then `scripts/guacd/verify.sh` (both need
  docker; `APT_MIRROR` / `UBUNTU_MIRROR` as for the other gates). Verify installs only the
  runtime packages in a clean container **and connects to an RDP target for real**; the
  plugins loading is not enough (1.6.0 on 26.04 loaded fine and crashed on the first frame).
  Look at the screenshots it writes next to the builds
- [ ] configure must detect FreeRDP 3 correctly: the build fails on purpose if it reports
  "freerdp structs have a context... no" for a FreeRDP 3 target (the `-Wno-error` in
  CPPFLAGS is what prevents that; see the comment in `in-container-build.sh`)
- [ ] Every archive ships `LICENSE`, `NOTICE` and `SOURCE` (Apache-2.0 requires the first two;
  `SOURCE` points at the exact source and scripts). libvncclient is GPL-2+ and comes from the
  distribution; never bundle it. Never call the build an Apache release (ASF trademark)

## 5d. System export / import (cross-instance migration): **run in full every release that touches it**

- [ ] **Layout**: "Data to include" is one item per row, name and count on one line with the count right-aligned and the description below; nothing wraps badly at 1280 px or phone width and the list stays inside the card
- [ ] **Unit (no DB)**: `pytest tests/test_system_transfer.py -q`, covering crypto seal/open
  (wrong passphrase → readable error, not 500), secrets round-trip for every
  representation (column / central / envelope / settings-blob), `registry.validate_registry()`
  returns empty (every table categorised), backward-compat coercion drops unknown columns
- [ ] **DB-backed** (`JTIPAM_TEST_DATABASE_URL` at head): export→import round-trip
  preserves UUIDs + FKs, secrets re-decrypt under the target key, `merge` is idempotent
  (2nd run all `updated`, no dup rows), `replace` wipes first, `dry_run` writes nothing
- [ ] **Backward compat**: an older/reduced export file (missing newer tables/columns)
  imports without error; the target schema_version mismatch shows a warning, not a failure
- [ ] **CLI**: `python -m app.cli.system_transfer export --scope … --out f.json --passphrase-stdin`
  then `import --file f.json --dry-run` then real `import`; counts correct, wrong
  passphrase exits non-zero
- [ ] **UI (admin → System Export / Import)**: pick scope + passphrase → generate →
  download; upload on a second instance → analyze (shows source version + counts +
  warnings) → dry-run preview → apply (merge and replace); non-admin gets 403 / no menu
- [ ] **End-to-end migration**: export full default scope from instance A, import into a
  clean instance B, then log in on B and confirm subnets / IP / devices / integrations
  are present, an integration actually connects (secret re-encrypted), SSH credential
  works, and TOTP still logs in
- [ ] **Security**: download / analyze / apply all require admin + validate task ownership;
  spool files are 0600 in a 0700 dir; no plaintext secret or passphrase in logs/responses
- [ ] **Import streams** (`tests/test_system_transfer_streaming.py`): on the scale dataset export the default scope
  (27.5 MB, 427k rows) and run `import --dry-run` under `/usr/bin/time -v`; peak RSS stays around 200 MB (it was
  1.36 GB before 2026-10-01) and the per-table counts match; a wrong passphrase is reported as such and replace mode
  never wipes anything before the file has been verified; no decrypted content is written to disk

## 5e. AI chat / MCP tools: **every release that touches tools, prompts, or the data they read**

Wrong AI answers do not look wrong: every number in them is real, just computed over the
wrong set. Unit tests pass because each tool returns exactly what it was asked for; the
defect is in *what the model was able to ask*.

- [ ] **Scope**: for each tool returning per-object data, ask a question naming one subnet /
  rack / location and confirm the answer contains only that scope. Regression to guard:
  "which hosts in 198.51.100.0/24 have no Wazuh agent" answered with the whole system
  because the tool had no subnet parameter at all (v0.5.194)
- [ ] **Schema exposes the scope**: the tool description tells the model it MUST pass the
  scope for a scoped question, and the reply carries `scope` so the answer can state coverage
- [ ] **No silent truncation**: every list tool returns `count` (total in scope) next to
  `returned`; ask something exceeding `limit` and confirm the answer says it is a partial list
  instead of presenting one page as the total
- [ ] **Permission tiers**: each new/changed tool sits in the right tier (mutating / admin /
  global-read / per-object) and `allowed_tool_names()` hides it from accounts that cannot call
  it. Verify through the actual AI chat with a restricted account, not only in unit tests
- [ ] **Identifiers from another table are mapped before a permission check**: `fdb_entries.device_id` /
  `arp_entries.device_id` are LibreNMS devices, not jt-ipam devices. Ask "which switch port is MAC …
  on?" as a department account that can see the switch: `trace_mac` must return the switch name and
  port (it compared the two kinds of id and never showed a port to anyone but an admin until
  2026-09-30); a switch the account cannot see stays hidden (`tests/test_mcp_rbac_scope.py`,
  `tests/test_rbac_gaps.py`)
- [ ] **Read-only stays read-only**: analysis/triage tools never write, never notify, never commit
- [ ] **Prompt injection**: attacker-controlled text (mDNS hostname, firewall rule description)
  stays fenced and truncated; the adversarial tests still pass
- [ ] **Facts come from tools, not arithmetic**: usage / free / count answers are fetched, never
  computed by the model from a CIDR

- [ ] **Cancellable**: while generating, Send becomes Stop; pressing it aborts the request
  (closing the connection also stops the LLM server), and the transcript says it stopped
- [ ] **Progress is visible**: connecting / thinking / which tool / composing / answering, each
  with the round number and elapsed seconds; **a bare spinner is indistinguishable from a hang**
- [ ] **An empty reply is never passed through**: the model is asked once more for a direct
  answer, and if it is still empty the reason is stated (length limit vs no text at all)
## 5f. Browser consoles (SSH / BMC / PVE): **whenever the terminal changes**

- [ ] **URLs are clickable**: when a TUI has broken a long URL across rows
  (`printf '%s\n' "$URL" | fold -w $(tput cols)` reproduces it), hovering the **second row**
  still recognises the whole URL, and the bar shows the full target
- [ ] **Only http/https open**, in a new tab with no opener (the text comes from the remote host)
- [ ] **Selection copy**: a URL split across rows copies as one usable address;
  **ordinary multi-line text must be left untouched**
- [ ] **No false joins**: a full-width line followed by unrelated text is not glued into a URL
- [ ] **SFTP sort mode**: with Folders first, directories lead in **both ascending and descending**
  order (putting the grouping inside the comparator inverts it on descending; that is the regression
  to watch); Mixed sorts purely by the column. Sorting by size or mtime honours the same mode.
  The choice is saved to user preferences and survives a reconnect or a different device
- [ ] **SFTP per-file limit (system setting)**: default 100 MB; a raised value sticks, and saving from an
  older page does not reset it; anything outside 1–102400 MB is refused with a message and reverted (it
  must **not** be clamped by the input and saved). Changing the limit runs the transfer path check
  **automatically**; the result gives upload/download speed and how long a file of the limit would take;
  a broken path names the kind (WebSocket blocked / 1009 message too big / cut mid-transfer / data not
  getting through). Existing spec: `e2e/sftp-limit-probe.spec.ts` (1009 simulated with routeWebSocket)
- [ ] **Large SFTP downloads**: over 64 MB, Chrome / Edge ask where to save and write to disk as data
  arrives (byte-identical, written in many pieces); other browsers fall back to memory (and refuse above
  2 GB with a message); over the limit is refused at once; progress shows while downloading.
  Existing spec: `e2e/sftp-stream-download.spec.ts` (needs `E2E_SFTP_ROOT`, `sftp-target.py` on 2223)
- [ ] **Run the path check on production too**, from outside through the edge reverse proxy; the dev
  machine's path does not have that layer
- [ ] Existing spec: `frontend/e2e/terminal-links.spec.ts` (needs `E2E_SSH_ADDRESS_ID/USER/PASS`,
  plus `can_ssh` on the user and `ssh_enabled` on the address; accept the host key on first use)

## 5e. Large-scale environments: **whenever sync, list pages, topology, exports or query patterns change**

The rule since GitHub issue #47 (a device with 30,000+ ports pushed an `IN` list past asyncpg's 32767
parameter limit): medium-sized test data cannot catch "one query fits" assumptions.

- [ ] Guard tests green: `tests/test_many_values_in.py` (no Python-list `IN` on sync paths, 30k values
  pass, batched writes), `tests/test_fk_indexes.py` (every foreign key has an index),
  `tests/test_topology_scale.py`, `tests/test_librenms_arp_sync.py` (an unchanged round costs a constant
  number of queries)
- [ ] Generate a large site: create `jt_ipam_scale` → `alembic upgrade head` →
  `POSTGRES_DB=jt_ipam_scale python -m tests.seed_scale` (2,000 /24s + a full /16, 145k IPs, 20k devices,
  200k ports with 40k on one device, 290k FDB, 100k leases, 500k IP changes)
- [ ] Point a backend at it and hit every GET: no 5xx, nothing taking more than a few seconds; the topology
  answers "too large" at 20k devices instead of freezing the backend
- [ ] Sync probe (fake API returning the same volume): a LibreNMS round finishes in minutes, and an
  unchanged round's query count does not grow with the number of rows
- [ ] Point the frontend at it: `e2e/all-routes.spec.ts` / `mobile-all-routes.spec.ts` green; open the /16
  subnet page and the 40k-port device page, and the longest main-thread block stays around 1.5 s or less
  (measure long tasks, do not eyeball)
- [ ] New lists, syncs and exports must answer: what happens at 100k IPs, tens of thousands of ports on one
  device, 100k leases (parameter limit, loading everything into memory, per-row queries, rendering
  everything at once, no pagination)
- [ ] **Run the GET sweep twice: as admin and as a broad non-admin account** (read on every section and on a
  location holding all devices). Admins skip visibility filtering, so the admin sweep alone never exercised
  it: an account that could see more than 32767 objects got a 500 from every list page and AI tool
  (2026-09-30). `tests/test_visibility_scale.py` pads the visible set to 40,000 ids; the `IN` guard in
  `tests/test_many_values_in.py` now scans all of `app/` and no longer trusts names containing "subnet"
- [ ] **Every integration's sync, not just LibreNMS** (fake upstream at the same volume, time + query count,
  an unchanged round must not grow with the rows): Wazuh 30k agents (`tests/test_wazuh_scale.py`, including
  SCA: at most 200 agents per round, oldest first, stops on HTTP 429), OCS (`tests/test_ocs_scale.py`),
  Zabbix, ESXi, DNS, AdGuard (`test_*_scale.py`), the five firewalls and Windows / Kea / ISC DHCP through
  `services/fw_sightings.py` (`tests/test_fw_sightings.py`). A duplicate key in one upstream response must
  not fail the sync
- [ ] **The site-wide liveness recompute** runs every 5 minutes over every IP: over ~6,500 IPs it used to
  exceed the parameter limit and never update statuses again (`tests/test_liveness_scale.py`, 8,000 IPs).
  On the scale DB an unchanged round is ~10 s and 3 queries
- [ ] **Background jobs on the scale DB** (anomaly detection, system diagnostics, pool usage, pruning,
  audit chain): each round completes in seconds; the audit chain is verified in batches of 5,000
  (`tests/test_audit_anchor.py`) so a first verification over millions of rows does not load them all
- [ ] **System export / import memory**: export the scale DB with `/usr/bin/time -f %M`; default scope
  stays around 150 MB RSS and the full scope around 350 MB (it was 1.7 GB / 5.4 GB before streaming); the
  file decodes to the same content (`tests/test_system_transfer.py::test_streamed_export_is_the_same_file_format`).
  Import into a fresh DB writes in batches of 1,000 with a per-row fallback (`::test_batched_import_isolates_a_bad_row`);
  note the import still parses the whole file in memory, so size the target host accordingly

## 6. Manual page review (browser, after deploy)

- [ ] Login / logout / theme switch (light / dark / auto)
- [ ] Subnets: list, tree, IP list (incl. idle-range rows spanning columns), edit
- [ ] Devices / racks: sorting (natural IP order), consistent action-button height,
  floor-plan upload + drag-to-place + select
- [ ] **Dashboard racks card** (bottom, `e2e/dashboard-racks.spec.ts`): unconfigured shows "Settings"; pick a room → its
  racks drawn in one row standing on the same floor (no border in the dark theme), names open the Racks page; switch to
  selected racks → only those; the setting survives a reload and another browser; more than 12 shows "N more" linking to
  the Racks page
  - the whole row uses one scale: a 42U rack is clearly taller than a 3-level shelf (each used to be shrunk to fit on
    its own, so they looked the same height); a 2×2 KALLAX stays square in the thumbnail, not squeezed narrower
  - the "Size" slider in its settings (50% to 300%): enlarging scales the whole row with proportions intact; it survives
    a reload and another browser (stored with the account)
- [ ] **MAC on the probe page**: the summary has a "MAC" row; a normal NIC shows MAC (vendor), a random MAC such as an
  iPhone's shows the "Random (private) address" tag (with an explanation on hover)
- [ ] **Probe cancel** (`tests/test_ip_identify.py`): "Cancel probe" while running → failed with "This probe was cancelled",
  the task shows cancelled, no notification; a later agent result does not turn it back to done; a new probe can start
  right away; cancelling a finished probe returns 409
- [ ] **Certificate SFTP host key** (`tests/test_cert_source_host_key.py`): after the first connection test or fetch the
  source settings show a SHA256 fingerprint; give the SFTP host a different host key → the fetch fails listing both
  fingerprints; after "Trust the host key again" the next fetch works and remembers the new one; changing the host clears
  the pin
- [ ] **HTTP check** (`tests/test_netdiag_http_guard.py`): the jt-ipam server's own LAN IP is refused; an account with no
  permissions gets 403
- [ ] **"Unmanaged" in the IP grid** (`tests/test_unmanaged_sightings.py`, `e2e/subnet-grid-unmanaged.spec.ts`): an agent with
  auto-create off scans a live address missing from IPAM → no IP record, the cell is a dashed orange box (faded after a
  day), the legend shows "Unmanaged (N)" and the free count drops, hover shows source / how long ago / MAC; clicking
  registers it and the cell turns normal; background probe data (liveness=false) does not count; addresses outside the
  agent's subnets are not kept; unauthorised-IP detection lists an address only the scan agent saw; the API returns 404
  without subnet read access; sightings not seen for 30 days are removed
- [ ] **Device type "Workstation" and auto-detection** (`tests/test_device_workstation_type.py`): create, edit, list
  filter and import ("workstation", "laptop", "PC") all accept it; an "other" device whose IPs have Windows 10/11 or macOS
  from Wazuh, RustDesk or OCS becomes a workstation after the next sync round; Windows Server becomes a server; Linux is
  left alone; a type changed by hand (even back to "other") is never auto-changed afterwards; a device created from the
  IP page's "Create device" gets Workstation right away; the topology legend's "Servers / other" group includes
  workstations; racks show a workstation colour
- [ ] **Dashboard card headers hold only the title (at most a count)**: no buttons, no subtitle text; the racks card's
  Settings button and scope sit at the top of its body
- [ ] **IP details "Last seen by source"** (`e2e/ip-seen-sources.spec.ts`): a section of its own with source / time / ago
  columns in a fixed order (scanner, LibreNMS, ARP, Wazuh, OCS, each firewall, AdGuard), the most recent row bold and
  tagged "Latest"; the basic fields no longer carry last-seen rows; on a phone "ago" moves under the time with no
  horizontal scroll. Clicking the LibreNMS / Wazuh / OCS time opens the device page scrolled to that card (outline flashes)
- [ ] **Last seen by source: verdict and sorting** (`e2e/ip-seen-sources.spec.ts`, `tests/test_ip_seen_rule.py`): the scanner
  within the limit reads "Counts · current", an old LibreNMS time "Counts · expired", DHCP lease and AdGuard "Not counted"
  (and follow the liveness sources in system settings); one click on Time puts the newest first; phones show three columns
  without horizontal scrolling; the IP list API carries no `liveness_rule`
- [ ] **SFTP name clashes** (`tests/test_sftp_upload_conflict.py`, `e2e/sftp.spec.ts`): uploading an existing name asks
  Overwrite / Keep both / Skip; Keep both creates "name (1).ext" and leaves the original; Overwrite replaces the content and
  keeps the permissions; with several clashes "do the same for the rest" asks once; cutting the link half way through an
  overwrite leaves the original intact and no `.jtipam-upload-` leftovers; overwriting works on SFTP servers without
  posix-rename
- [ ] **Device type column on the subnet page's IP list**: the column picker offers it and it looks the same as on the
  Addresses page (icon and name, model on hover)
- [ ] **Device type vendor and ambiguous guesses** (`tests/test_device_identity.py`, `tests/test_recog.py`): a SuperMicro
  machine is no longer labelled HP (jt-ipam's OUI table wins); Linux vs HP P2000 within a point or two comes out as server;
  port 8006 open means hypervisor
- [ ] **SFTP rate** (`e2e/sftp.spec.ts`): large uploads and downloads show "MB/s · about … left" after the progress; with the
  link cut or throttled to almost nothing it turns into "0 B/s · stalled" within seconds
- [ ] **GraphQL removed**: `POST /graphql` is no longer GraphQL (404, or 405 from the static frontend); the version page's
  package list has no strawberry
- [ ] **Agent OS probe with a slow service** (`tests/test_device_identity.py`): a periodic OS probe of a host with PVE's 8006
  open ends up with a device type (it used to time out with nothing)
- [ ] **Virtual/physical shows the guest kind** (`tests/test_virt_correlation.py`): a PVE LXC reads "Container · LXC",
  qemu "Virtual machine · KVM", VMware "Virtual machine · VMware", the same on IP details and the device page
- [ ] **Counts in subnet page card headers**: "Address ranges (pools)" and "IP list" show the count as a tag next to the
  title, not in brackets
- [ ] Topology: nodes / links, VPN pairing links, legend
- [ ] **MAC history** (`tests/test_mac_history.py`, `e2e/mac-history.spec.ts`): typing a full MAC into global search (upper
  case, dashes, Cisco dots all work) shows "Full history of …" on top, Enter goes straight there and clears the box; the MAC
  in IP details, old/new MAC values in the change history and MACs in anomaly detection all link there. The page: IPs used
  (in-use first, first and last seen, evidence, status light; IPs whose record was deleted still listed and marked),
  switch ports (LibreNMS and MikroTik), timeline (took / left, previous and next MAC), DHCP reservations, device ports and
  VM interfaces. Random MACs carry a tag and an explanation; "probably the same device" only lists handovers where the
  host name stayed the same. A department account sees only IPs in granted subnets and granted devices, and no DHCP or
  VMs (the page says so). A non-MAC returns `mac_invalid`. On production, check a MAC that really moved against the IP
  details change history.
- [ ] **Console relay through scan agents** (issue #24 phase 2; `tests/test_console_relay.py`, `e2e/console-relay.spec.ts`).
  Setup: two containers as customer sites, each with a dummy interface 10.99.0.5/24 (overlapping), sshd, a marker file and a
  scan agent dialing back to the backend (no relay variables set on the agent host); two 10.99.0.0/24 subnets assigned to their own agent as
  scan agent and console exit; the backend host cannot reach 10.99.0.5. Check: SFTP to each IP lists its own marker file and the
  status bar says "via scan agent: <name>"; an SSH session works the same way; a second worker process gets the port over Redis.
  Everything is set in the web UI: with the system switch and "Allow console relay" on the agent page turned on, the agent
  host needs nothing and consoles connect right away (no waiting for the next poll); setting Allowed ports to 2222 lets SSH
  on 2222 through and refuses 22 (`relay_port_not_allowed`); an invalid list (`abc`, `1-70000`) returns
  `relay_ports_invalid`. Refusals, never direct: system switch off, agent not allowed (the poll hands out an empty scope and
  the agent relays nothing), agent too old, the host owner refusing with `JT_IPAM_RELAY=0` (`relay_agent_host_off`; the
  agent also refuses when the server is forged to think it is on), target outside the agent's subnets, port not allowed,
  agent offline (`relay_agent_timeout` after 15 s). `JT_IPAM_RELAY_PORTS` / `_MAX` / `_CIDRS` on the agent host can only
  narrow, and the agent page's status tag lists those local limits. Restarting the agent and relaying right away works (no lost job).
  Audit has `console_relay` with bytes each way. Subnet edit shows the subnet's scan agent as a console exit (greyed out with
  the reason when it cannot relay); changing the scan agent while the exit points at the old one is refused. Upgrade adds the
  nginx location (`grep scan-agents/relay /etc/nginx/sites-available/jt-ipam`, `nginx -t`).
- [ ] **Disabled jump host refuses** (`jump_host_disabled`) instead of connecting directly; IP edit saves a per-IP jump host or agent.
- [ ] **Create IPs from the LibreNMS ARP table** (#48, `tests/test_librenms_arp_autocreate.py`): LibreNMS integration →
  edit → "Create IPs from the ARP table" is off on a new and on an upgraded site. Turn it on → the warning (no longer
  under Unauthorized IPs, not liveness evidence) and two options appear: "Require a switch MAC table sighting" (on) and
  "Skip DHCP dynamic ranges" (on); unticking the first shows the ARP-only warning. Sync → new addresses have source
  "LibreNMS ARP", the auto-collected tag, a MAC and a "created" entry in the change history; the Tasks summary shows
  "IPs created from ARP N" and the top reasons for the rest. A device unplugged hours ago that still sits in the router's
  ARP cache is NOT created while the MAC-table option is on. Overlapping subnets without a scope, proxy ARP, broadcast
  and network addresses, released (cooldown) addresses and DHCP pools are skipped. The created IPs do not turn online on
  ARP alone. The audit log entry for the settings change lists the changed fields.
- [ ] **Site-to-site VPN from every vendor** (`tests/test_vpn_site_to_site.py`): the default "Subnets only" view has VPN
  lines; FortiGate IPsec tunnels, Palo Alto IPsec tunnels ("Site-to-site VPN" in the integration settings, on by
  default; Test connection shows `vpn_flow`) and MikroTik WireGuard all know their own device (left side of
  "Pairing / peer" on the site-to-site VPN page). With both ends in jt-ipam they become one line (public keys for
  WireGuard, endpoint addresses for IPsec, across vendors too); an unknown far end is drawn as a remote site.
  ⚠️ Palo Alto has not been checked against a real device: on a customer site compare the `vpn_flow` row count and
  tunnel states.
- [ ] Scan agents / sync jobs: pages render, no console errors
- [ ] **Table column widths** (`src/utils/__tests__/resizableColumns.test.ts`): on a wide screen (1800px) the date
  columns of the OCS agent list, audit log and task history do not wrap and spare width is shared in proportion; widening
  one column changes only that column (columns resized earlier stay put) with space left empty on the right; going wider
  than the screen scrolls horizontally; the mobile sweep shows no horizontal overflow
- [ ] **Tasks page** (`e2e/tasks-filters.spec.ts`, `tests/test_tasks_page_sources.py`): history can be searched by type, target
  and error and filtered by type, status and trigger, and the total follows; after a RustDesk agent report there is a
  `rustdesk.sync` row (one per server, updated on the next report), ISC DHCP gives `isc_dhcp.sync`; "update now" for
  OUI, Recog and GeoIP adds a manual row (who clicked), a timer run is one scheduled row; deleting a RustDesk server or any
  integration removes its scheduled row; probes, agent reports and database refreshes show their outcome instead of four
  zeros; the diagnostics "Background jobs" check only counts scheduled syncs (stop jt-ipam-sync.timer for a day and it
  must warn even while RustDesk keeps reporting)
- [ ] **Docs site (GitHub Pages)**, on every release that adds a feature or an integration: the feature map
  (`docs/features.html`) and the home page integration badges name it (each product, not a category such as
  "DNS"); every feature-map item fits on one line at desktop width in zh / en / ja; every section heading has a
  `#` link with an English anchor and `page.html#anchor` opens scrolled to it (API manual subsections too);
  `git ls-files '*.md' '*.html' | xargs grep -lP '\x{FF0F}'` finds nothing (docs use a half-width slash)

## 7. pfSense integration (Admin → 整合 pfSense)

> Prereq on the pfSense (CE 2.8.x): install **pfSense-pkg-RESTAPI** (pfrest.org), then System →
> REST API → Settings add **"API Key"** to auth methods, and create a key under Keys.

- [ ] Add instance: API URL + X-API-Key, **Verify TLS off** for a self-signed cert; save (key write-only, never returned).
- [ ] **Test connection** → success with the pfSense version.
- [ ] **Sync now** (ARP + aliases + rules on; **DHCP off** if another DHCP server owns the LAN) → counts return; an
  in-scope ARP IP gets `last_seen` (source `pfsense`) + MAC; aliases/rules counts reflect the box.
- [ ] **Field-name regression**: ARP/DHCP use `ip_address`/`mac_address` (not `ip`/`mac`); `hostname == "?"` → blank.
- [ ] **Scope safety**: with `scope_subnet_ids` set, stamping only hits IPs in those subnets (overlap-safe `.limit(1)`).
- [ ] **Rules / NAT viewer** (eye action) renders synced rules + NAT counts.
- [ ] **Graylog DSV** (Expose DSV on + a Graylog DSV token set): `GET /api/v1/lookup/pfsense/{id}/aliases?token=…`
  and `…/rules?token=…` return CSV/TSV; **wrong token → 401**; `expose_dsv` off → 404.
- [ ] Delete instance; periodic `jt-ipam-sync` picks up enabled instances every ~5 min without errors.

## 7b. VMware ESXi / vCenter integration (Admin → 整合 VMware): **Beta**

> The SOAP endpoint is always `<url>/sdk`. One implementation covers **both** a standalone ESXi
> host and vCenter: they are the same VIM API, and ContainerView absorbs the depth difference.
> Use a **read-only** account: this integration never writes. Free/unlicensed ESXi exposes the
> API read-only anyway, which is exactly what is needed here.

- [ ] Add instance: URL + username/password, **Verify TLS off** for a self-signed cert; save
  (password write-only, never returned). Editing with an empty password leaves it unchanged.
- [ ] **Test connection** → step-by-step diagnostics: RetrieveServiceContent (product + version),
  Login, RetrievePropertiesEx (VM count). A wrong password must fail at **Login** with VMware's own
  message, not a bare "server error"; VMware returns auth failures as a SOAP Fault over HTTP 500.
- [ ] **Sync now** → VM count returns; clusters list shows the instance with type `vmware`;
  VMs carry name / power state / vCPU / memory / host.
- [ ] **Field reality check (first real hardware run)**: compare a few VMs against the vSphere client.
  Powered-off VMs have no `guest.*`, VMs without VMware Tools have no IP, templates have no
  `runtime.host`. None of these may break the sync; they should simply come back empty.
- [ ] **Paging**: on a vCenter with more than 200 VMs, the count matches the vSphere client
  (a dropped continuation token loses the rest **silently**).
- [ ] **IP matching**: an in-scope IP reported by VMware Tools links to the existing address;
  an address not in IPAM is **not** created. With overlapping subnets and no scope set, the
  ambiguous address is skipped rather than guessed.
- [ ] **Deleted VM**: remove a VM in vSphere → next sync removes it from the list.
- [ ] **PVE regression (shared tables)**: Proxmox clusters/VMs/interfaces are untouched by an ESXi
  sync, `legacy_vmid` and `kind=ct` still correct, and 進階 → 虛擬化 (Proxmox VE) still lists only PVE
  while 虛擬化 (VMware) lists only VMware. Device / IP links from PVE VMs still resolve.
- [ ] **Long external names (issue #25)**: a VM on an NSX-T portgroup whose name exceeds 64 chars
  syncs without error, and the full name (not a truncated one) shows on the VM's interface. The
  same goes for an ESXi host FQDN longer than 128 chars in `node`. A name coming from a third-party
  platform has no length we get to assume.
- [ ] Delete instance; periodic `jt-ipam-sync` picks up enabled instances every ~5 min without errors.

## 7b2. MikroTik RouterOS integration (Admin → 整合 MikroTik): **Beta**

> **The point of this integration is not to slow the router down.** At the site that asked for it,
> the MikroTik boxes are the *main* routers, so the safeguards are the feature; test them, not
> just the field parsing. RouterOS needs `www-ssl` enabled and an account with `api` + `read`.

- [ ] Add router: URL + username/password, **Verify TLS off** for a self-signed cert; save
  (password write-only, never returned). Editing with an empty password leaves it unchanged.
- [ ] **Test connection** reports RouterOS version, board name, identity, CPU before/after, and
  **rows + seconds for every endpoint**. Numbers are the whole point: "ARP 12,000 rows / 3.2s" is
  how an administrator decides whether to enable that section.
- [ ] A menu the device does not have (`/ip/dhcp-server` on a switch, `/interface/wireguard` on
  RouterOS 7.0) shows as **absent, not an error**; a switch must not finish a sync covered in red.
- [ ] **RouterOS 6.x is named**: pointing at a v6 device must say "this is RouterOS 6.x, which has
  no REST API", not a vague connection failure.
- [ ] **Sequential, never parallel**: watch the router's own connection/CPU graph during a sync;
  only one request should be in flight at a time. (Packet capture, or RouterOS `/tool/profile`.)
- [ ] **Back-off works**: lower the CPU threshold to something the router already exceeds (e.g. 1%)
  and sync → the round stops early, the list shows the「提早停止」tag with a reason, and
  `last_error` stays **empty** (stopping early is not a failure).
- [ ] **Size cap**: set the response cap to 1 MiB on a router with a large address list → that
  section aborts with a readable message naming the limit, and **the other sections still run**.
- [ ] **ARP is reachable-only**: an entry the router shows as `stale` or `permanent` must not stamp
  the IP as online. (Check `arp_seen` on the IP: only `reachable` entries may appear.)
- [ ] **DHCP three-table join**: ranges only appear when pool ↔ dhcp-server ↔ network line up; a
  pool used by PPP/hotspot (no DHCP server pointing at it) must **not** show up as a DHCP range.
  A subnet that already has a gateway or DNS set is **not** overwritten.
- [ ] **Rule order is preserved**: the read-only view lists rules in the router's own order
  (RouterOS matches top-down). Moving a rule in Winbox must **not** raise a rule-change alert;
  editing one must.
- [ ] Delete the router → its `dhcp_pool_ranges` and `nat_translations` rows go with it, and
  no other source's rows are touched; its FDB and neighbors go too, and the ports it created are
  released (uncabled ones deleted, cabled ones kept as manual ports).

**Phase 2: interfaces, neighbors, FDB (migration 0170, `tests/test_mikrotik_phase2.py`)**
- [ ] **Device mapping**: the settings "Device" field searches by name on the server (found even with
  tens of thousands of devices); left empty, a sync fills in the device that owns the IP of the API
  address. An unknown device returns `422 ros_device_not_found`.
- [ ] **No device is not a failure**: an API address that matches no device-linked IP → the
  interface / neighbor / FDB sections are skipped, the list shows a「待指定裝置」(Device needed) tag
  next to Last sync (reason on hover), and `last_error` stays **empty**.
- [ ] **Interfaces → ports**: the device's ports show the physical ports (ether / sfp / wlan…) with
  MAC and comment; virtual interfaces (bridge / vlan / pppoe / wg) must **not** appear. Remove an
  interface on the router → that port is deleted next round; cabled and hand-made ports are untouched.
- [ ] **Neighbors**: Advanced → 路由器 (MikroTik), "Neighbors" tab, lists local port, neighbor name, remote port,
  IP, MAC, platform and discovery protocol; a name links to the device when the announced address or
  MAC matches **exactly one** device (overlapping subnets: no guess). A neighbor seen on both the
  physical port and the bridge is listed once (the physical port).
- [ ] **Topology**: neighbors become backbone links between the two devices (label "local ↔ remote",
  via "Neighbor discovery (MikroTik)", evidence "monitored"); with FDB on, hosts on router ports are
  drawn too.
- [ ] **FDB**: off by default (a large bridge can be tens of thousands of rows; check the row count in
  Test connection first). When on, the router's own MACs (`local=true`) and rows on the bridge
  interface itself are skipped. **On a site with MikroTik and no LibreNMS**, IPs still get a switch
  port ("device / port", same rule as LibreNMS).
- [ ] **Every FDB reader names the MikroTik switch**: AI chat "where is this MAC" / "which port is this
  IP on", VLAN members, and `/api/v1/librenms/fdb` (`source=mikrotik`, `switch_device_id`) show the
  router's device name, not "?" or blank.

## 7l. Console jump host (issue #24 phase 1): **whenever a console or the routing changes**

> The failure mode here is not "cannot connect", it is **"connected to someone else"**. Sites that
> need a jump host are usually the sites with overlapping private ranges, so a console that quietly
> falls back to a direct connection reaches a *different customer's* machine, with no error anywhere.
> Test every console, not just SSH.

**Standing up a real jump host takes two minutes** (do not skip this and test only the unit level):

```bash
D=/tmp/jump; mkdir -p $D && cd $D
ssh-keygen -q -t ed25519 -f hostkey -N ''
ssh-keygen -q -t ed25519 -f clientkey -N ''
cp clientkey.pub authorized_keys
printf 'Port 2242\nListenAddress 127.0.0.1\nHostKey %s/hostkey\nPidFile %s/sshd.pid\n' $D $D > sshd_config
printf 'AuthorizedKeysFile %s/authorized_keys\nPermitRootLogin prohibit-password\n' $D >> sshd_config
printf 'PasswordAuthentication no\nUsePAM no\nStrictModes no\nAllowTcpForwarding yes\n' >> sshd_config
printf 'Subsystem sftp /usr/lib/openssh/sftp-server\n' >> sshd_config
/usr/sbin/sshd -f $D/sshd_config -E $D/sshd.log
```

`StrictModes no` is needed because sshd rejects an `authorized_keys` under a world-writable `/tmp`.
The same sshd can play both roles: register it as the jump host, and point the target IP record at
`127.0.0.1` port 2242 so the forward lands back on it.

- [ ] **Fingerprint first**: a jump host with no pinned host key must **refuse to connect** and say so.
  Test connection returns the fingerprint *without* sending credentials; only after Trust and save
  does it actually log in.
- [ ] **Wrong fingerprint**: change the pinned value → connecting must fail with a man-in-the-middle
  warning, not a generic error.
- [ ] **Resolution order**: set a jump host on the subnet and a *different* one on the IP → the IP
  wins. Disable the jump host → the console **refuses** with "jump host is disabled" (since 2026-10-02:
  falling back to direct on overlapping networks reaches the wrong host); removing the assignment
  is the way to connect directly.
- [ ] **All four tunnelled consoles** (SSH / SFTP / RDP / VNC), each through the jump:
  - SSH: the status bar shows「經由跳板：<name>」and a real shell responds
  - SFTP: a directory listing appears (this proves both directions, not just server→browser)
  - RDP / VNC: check the **port**, not just the host; aardwolf's `create_connection_newtarget()`
    replaces the ip/hostname but keeps the port from the URL, so a missing port means connecting to
    `127.0.0.1:3389`, the backend host itself
- [ ] **BMC refuses**: an address with a jump host must return a readable "IPMI is UDP, an SSH
  tunnel only forwards TCP" error, **never** a silent direct connection
- [ ] **Connection reuse and limit**: open several sessions to the same jump host → one SSH
  connection is shared (check with `ss -tnp` on the jump); exceeding `max_sessions` is refused with
  a readable message; after the last session closes the connection goes away
- [ ] **Failure returns the reference**: force a forward failure a few times (wrong target port),
  then confirm normal sessions still work; a leaked reference count silently uses up the limit
- [ ] **Session lifetime**: close the browser tab → the forward disappears from the jump host
- [ ] **Deleting a jump host** warns how many subnets/addresses will fall back to direct
- [ ] **Requirements guide** (`e2e/jump-hosts.spec.ts`): both the Requirements button and "What does a jump host need?" in
  the create dialog open it; it covers system, network, forwarding, account (no root or shell needed), authentication
  (passphrase-protected keys not supported) and host key; following the example on a clean Debian/Ubuntu (OpenSSH) host,
  an SSH console through it works, and an interactive `ssh -tt` with that key is refused (PTY allocation request failed)
- [ ] Audit records `via_jump_host` on every session open

## 7m. guacd console engine: **whenever a console, guacd or its build changes**

guacd is the default engine for RDP and VNC (since 2026-09-27; migration 0158 switches existing
installs), and SSH can use it (Admin → System settings, per protocol). Switching must not change
what a console is allowed to do.

- [ ] Defaults: on a fresh install the settings page shows "guacd (default)" for RDP and VNC and
  "Built-in (default)" for SSH; after upgrading an old site RDP / VNC are guacd
  (`frontend/e2e/rdp-engine.spec.ts`, `tests/test_console_engine_default.py`)
- [ ] guacd is required: Version info → Required components lists it (version, running); aardwolf
  is under Optional
- [ ] The security section of System settings is one setting per row: name and explanation on the left, the control on
  the right, a divider between rows; missing packages, guacd not running and the transfer path result span the full
  row under that setting; at phone width the row stacks
- [ ] Overlays sit above the AI assistant button: a confirmation / dropdown that opens in the bottom-right
  corner can be clicked where it overlaps the button (`frontend/e2e/chat-fab-overlays.spec.ts`)
- [ ] The Required components card stays readable with a long guacd version string (`… for Ubuntu
  24.04 LTS (amd64)`): the name column is not squeezed, the status is on the right, the version (without
  the OS suffix) is under the name, at desktop and phone widths (`frontend/e2e/version-required-deps.spec.ts`)
- [ ] With guacd stopped, RDP / VNC **still connect** (built-in engine fallback, if the optional
  aardwolf is present), the settings page shows guacd red and doctor / System check fail; a session does not hang when guacd goes up or down in
  the middle (the engine travels in the ticket and the WebSocket follows it)

- [ ] `frontend/e2e/console-guacd.spec.ts` against a local guacd and the three targets (see the file
  header: xrdp container on 3389, `e2e/fixtures/vnc-target.py` on 5999, an sshd on 2222). It checks
  that the screen is really painted (pixels, not just a canvas), that keys and Chinese leave as
  Guacamole `key` instructions, and that Ctrl+Shift+V sends the clipboard **before** the V
- [ ] Look at the screen yourself once per protocol (the test cannot read text):
  RDP types, VNC shows the target, SSH shows the prompt and **Chinese is full width** (a narrow,
  tiny glyph means guacd is not running under a UTF-8 locale; the unit sets `LANG=C.UTF-8`)
- [ ] SSH: an already pinned host key must be accepted by guacd (our patch
  `scripts/guacd/patches/0001` makes libssh2 negotiate the pinned key type); a changed key must
  still fail with the "host key does not match" message
- [ ] Credentials never reach the browser: the WebSocket carries the config message, then only
  Guacamole instructions; the server drops anything but key/mouse/size/clipboard/sync/nop/…
  (`tests/test_guacd.py::test_relay_forwards_allowed_and_drops_the_rest`)
- [ ] Clipboard policy is unchanged by the engine: RDP paste only when "RDP clipboard paste" is on,
  nothing back from the remote; VNC none; SSH copy and paste
- [ ] A background tab stays connected for more than 5 minutes (browsers throttle timers to once a
  minute there; the server sends the keep-alive, not the page)
- [ ] `sudo jt-ipam.sh doctor` and Admin → System check show guacd; stopping `jt-ipam-guacd` must turn
  both red with the fix and say the built-in engine is in use; when the built-in
  engine is unavailable too (no aardwolf, say), a ticket request must answer with a readable 503
- [ ] VNC username: on a server that asks for one (the VeNCrypt target on 5998 in the spec header)
  an empty username must say "enter the username", a filled one must connect; a wrong password must
  say "wrong username or password", not "host unreachable"; unreachable only when it really is (TCP
  is probed only **after** guacd failed: TigerVNC counts a bare connect/close as an authentication
  failure and blocks the source after a few; if everything fails halfway, look for `blacklisted` in
  the target's log)
- [ ] The status bar names the engine of this connection ("Engine: guacd" …); RDP / VNC carry no Beta mark
- [ ] **High-DPI screens**: on a Retina / 200% display the remote screen is sized in device pixels (sharp, not
  blurred) and SSH text is not twice as large; **A- / A+ change the SSH font size during a guacd session** and
  the size is remembered (only the font size reaches guacd, validated)
- [ ] Known limitation to keep in mind: in the SSH terminal, the first Chinese character typed on a
  line may not be drawn until the line is redrawn (Ctrl+L); the command itself is correct

## 7b3. Standalone Kea / ISC DHCP servers (issue #45): **whenever these integrations, the agent's dhcpd report or the shared DHCP write layer change**

- [ ] **A real Kea round trip** (a throwaway container is enough: Ubuntu 24.04 packages Kea 2.4 behind the Control
  Agent; ISC's own repository has Kea 3.0 for the direct socket): test connection returns the version and the mode
  (Control Agent / direct); a sync writes pools (range and CIDR forms, subnets under shared networks), reservations
  and leases (the existing IP is marked leased, MAC source kea_dhcp, host name); works with and without host_cmds;
  without lease_cmds pools still sync and the page says so; a wrong password fails with the 401 reason.
  ⚠️ The backend's outbound guard blocks loopback: bind Kea on the docker bridge (172.17.0.1) and enable
  OUTBOUND_ALLOW_PRIVATE on the local backend
- [ ] **A real isc-dhcp-server round trip**: the distribution's default dhcpd.conf (full of commented-out examples)
  yields nothing; `include` files are followed; the secret in a `key` block never appears in a report; after a
  client takes a lease the agent reads the real dhcpd.leases → fixed addresses are marked reserved, leases leased;
  a later record for the same address overrides an earlier one
- [ ] The agent reads the files only when the server assigns it an ISC source (`dhcpd` in the poll response);
  another agent cannot report for a source that is not its own (404); one agent serves one source
- [ ] An unreadable file (permissions, wrong path) keeps what was there and the last error names the file and the
  reason; an agent silent for 3× its report interval marks the source as failing (health alert)
- [ ] Deleting a source takes back its pools / reservations / leases / host names from the shared tables
- [ ] `e2e/dhcp-standalone.spec.ts`: a failing Kea test connection shows the real reason (not the browser's own
  15-second timeout); ISC file status; an agent already in use is disabled in the picker

## 7b4. RustDesk Server (open source): **whenever this integration, the RustDesk agent or the IP detail change**

- [ ] **OS source** (`tests/test_os_sources_rustdesk_wazuh.py`): the last entry of the OS precedence on the name / ARP
  sources page is "RustDesk client" (also appended on upgraded sites); an IP whose only OS comes from RustDesk shows it
  (source: RustDesk client); with the scan agent or Wazuh the order applies; ambiguous RustDesk matches do not count.
  A Windows 11 Wazuh agent shows "Microsoft Windows 11 Pro" on the device page and the Wazuh page, not windows 10.0.x

- [ ] **A real RustDesk Server round trip** (official deb, `/var/lib/rustdesk-server`; `tests/test_agent_rustdesk.py`,
  `tests/test_rustdesk.py`): the agent reads only id / created_at / info.ip (never pk / uuid, never `id_ed25519`);
  `::ffff:` addresses become IPv4; the online count matches what hbbs reports; the online query goes to the host's own
  address (from 127.0.0.1 hbbs answers as its text admin console); a non-default `PORT` in `.env` is followed
- [ ] **Dedicated RustDesk agent install** (`agent/jt-ipam-rustdesk-agent-installer.sh`, a clean Debian / Ubuntu with the
  official RustDesk Server deb): Add a server → the dialog shows the one-line install command with that server's key;
  run it on the RustDesk host → `jt-ipam-rustdesk-agent` is active, runs as the owner of `/var/lib/rustdesk-server`
  (`systemctl show -p User`), the directory is read-only for it (`touch` from `nsenter`/a test fails), the config is
  root 0600, and the agent column turns "Connected" with host, source IP and version within ~10 s. Re-running upgrades
  in place; `JT_IPAM_UNINSTALL=1` removes service, program and config and leaves RustDesk untouched
- [ ] **Agent key**: shown once on Add, again via "Install command" (audited `view_agent_key`); "New key" makes the old
  key fail at once (agent logs 401 and stops receiving); deleting the server makes the agent's polls fail; a key cannot
  write another server's data (409); a server created before the dedicated agent shows "No key" with "Generate key"
- [ ] **Test / Sync now**: Test lists each check (data directory, database, public key, hbbs version, online query,
  receiver) with the real reason when one fails (e.g. port 21114 taken); with no agent connected it says so and times
  out after 60 s; Sync now reports within ~10 s (last report time changes); a disabled server refuses Sync now and the
  agent stops reading and listening but keeps polling
- [ ] **Page layout** (`e2e/rustdesk.spec.ts`): tabs RustDesk servers / Devices / Connection audit (`?tab=` kept in the
  URL); edit / test / sync now / install command visible without horizontal scrolling at 1280 px (pinned column, no
  text showing through it in dark mode); the scan agents page no longer lists anything for RustDesk
- [ ] An unreadable database keeps the device list and the last error names the path and reason; a failed online
  query keeps the last state; a truncated report deletes nothing; a device removed from hbbs is removed here; an
  agent silent for 3x its interval raises a health alert
- [ ] Mapping: a unique IP that was online within 7 days is mapped; never seen online / offline over 7 days / three or
  more IDs on one IP (NAT) / two online on one IP / overlapping subnets / unmanaged IP are not, and the page says why
- [ ] IP detail shows the ID and online state; the "RustDesk" button's link is
  `rustdesk://connect/<id>@<client address>?key=<public key>` with no password, opens the installed client, and is
  missing for users without remote console rights (they still see the ID)
- [ ] `e2e/rustdesk.spec.ts`: server row (version, counts, agent host), device search / online filter / mapping labels,
  jump to the IP, the connect link, client address validation, install command, test round trip, sync now; check
  zh / en / ja once
- [ ] **Client report receiver** (RustDesk agent, `tests/test_agent_rustdesk_api.py`, `tests/test_rustdesk_contract.py`):
  listens on 21114 only while the server is enabled and "Receive client reports" is on (switch it off → port closed;
  a bind failure shows on the page); a real client
  with an empty API server field sends heartbeat / sysinfo within a minute; heartbeat answer is always `{}`, never
  strategy / disconnect / modified_at; a wrong uuid is dropped and counted; the uuid appears in no forwarded payload
  and no log; 64 KB / 10 s / per-IP rate and connection limits; a malformed event is skipped server-side (`rejected`)
  instead of failing the batch
- [ ] **Connection audit and alarms**: connect from another machine with a password, transfer a file, close → the audit
  tab shows connected → authenticated (peer ID, name, type) → file → closed; six wrong passwords → alarm row and one
  `rustdesk.alarm` notification (not one per attempt); the notification link opens the audit tab; audit older than
  400 days is pruned
- [ ] **Multi-signal mapping**: the heartbeat source IP wins over a NAT-shared registered IP; a matching host name is
  listed as evidence; a host name differing from the record gives "Host name differs" and no mapping only when the
  registered IP is the sole evidence (a fresh heartbeat from that address still maps it); a name-only match is a
  suggestion; generic names (localhost, ubuntu, desktop…) are not evidence
- [ ] **Per-IP RustDesk switch** (`test_connect_button_needs_the_per_ip_switch`, `e2e/rustdesk.spec.ts`): the connect
  button appears only after "Enable RustDesk connection" is on for that IP (admin too), carries the "Local" badge,
  and disappears when switched off; the switch shows only for IPs mapped to a RustDesk device; the IP page RustDesk
  row has no online state / last online / host name, and "Last seen by source" lists "RustDesk client"
- [ ] **Identify updates the IP's device type** (`test_device_kind_identify.py`): run Identify on a camera / printer
  whose IP shows "server" → the IP page shows the identified type afterwards; the next periodic cycle keeps it (no
  `kind_changed` entry); a periodic result with service evidence of another device still changes it
- [ ] **Device type column** (`test_device_kind_columns.py`): Connections, Wazuh / OCS "IPs without an agent",
  Anomalies and Exposed services offer 設備類型 in the column picker (default shown where noted), sort by it (the
  missing-agent lists sort on the server with `sort=device_kind`, empty last) and export it
- [ ] **IP form save keeps the host name** (`test_ip_edit_keeps_hostname.py`): open an IP whose name has no source
  observation, change only the description, save → the host name stays and no `hostname_changed` entry appears
- [ ] **Host name source `rustdesk`** (`test_reported_hostname_feeds_the_ip_record_last`): a mapped device's reported
  name fills an IP that has no other name; an IP named by DNS / another source keeps that name; the source shows last
  in the host name order settings as "RustDesk client"; generic names are not used; the name is withdrawn when the
  device is no longer mapped and when the RustDesk server is deleted
- [ ] **RustDesk-compatible web connection: real round trip** (test target `scripts/rustdesk-test-target/run.sh up`, wired to
  a disposable dev database with `seed_jtipam.py` from the same folder; unit tests `tests/test_rustdesk_web_proto.py`,
  `tests/test_rustdesk_web_net.py`, `tests/test_rustdesk_web_console.py`, frontend `src/rdweb/__tests__/`): turn on "Web
  connection" in the RustDesk server form and set the hbbs address (or leave it empty to use the agent's address) → the
  RustDesk button on the IP page opens a new tab; enter the device password → the picture shows within seconds; switch the
  transport to WebSocket and connect again, same result; backend logs and audit contain no password, hash or key
- [ ] **Login**: the right password connects at once; a wrong password asks again and the right one then connects **without
  reconnecting**; an empty password pops up the approval dialog on the device while this side shows "Waiting for approval"
  (the test target has no connection manager window, so check this on a real desktop); 3 wrong passwords → jt-ipam blocks
  first (no fourth attempt, new tickets get 429) and the device never reaches its own limit of 6; a device with two-factor
  login asks for the code and a wrong code can be retyped
- [ ] **Picture**: VP9 shows; after the device changes resolution the picture is right; two tabs connected to the same device
  both work; a tab frozen for 10 seconds (or put in the background) recovers without stalling or garbage; a device with a
  hardware H.264 encoder also shows a picture with H.264 (if not, note it and stop advertising it); "Fit" and "Original
  size" both work
- [ ] **Input**: left, right and middle button, double click, drag (a window can be dragged), wheel direction (scrolling down
  moves the page down); the four corners are exact (in the test target measure with
  `docker exec rdtest-client sh -c 'DISPLAY=:0 xdotool getmouselocation'`); typing is right with Chinese and English keyboard
  layouts; CapsLock on and off; the numeric keypad (NumLock on and off); the Ctrl+Alt+Del and "Lock screen" buttons; holding
  Shift while switching to another window and back leaves no stuck key; view only sends no input
- [ ] **Remote cursor** (appendix E of the spec; unit tests `src/rdweb/__tests__/cursor.test.ts`): in the test target,
  move over a text field → the local pointer becomes a text cursor, sized with the picture (check "Fit" and "Original
  size"); when the device hides its cursor the local pointer is hidden too;
  `docker exec rdtest-client sh -c 'DISPLAY=:0 xdotool mousemove 200 200'` → a remote cursor appears at that spot and
  goes away when you move the mouse locally (or after 3 seconds); switching displays or reconnecting brings back the
  normal pointer; a device whose picture already contains the cursor shows only one cursor; repeat on a real Windows
  device
- [ ] **Keepalive**: connected and untouched for 5 minutes, the session stays up (neither the hbbr nor the device 30-second
  idle limit triggers)
- [ ] **Automatic reconnect** (spec appendix G; frontend `src/rdweb/__tests__/reconnect.test.ts`,
  `src/components/__tests__/rustdeskReconnect.test.ts`): connected to the test target, run `docker restart rdtest-client`
  → the page shows "Connection lost" with a countdown ("reconnecting in N s, attempt k of 8") and **Reconnect now** /
  **Cancel**, never the manual "Reconnect" state; once the device is back it connects by itself and the picture shows;
  every attempt has its own ticket and `rustdesk.web_session_open` / `rustdesk.web_session_close` entries. Restart the
  jt-ipam backend during a session → same. **Cancel** goes back to "Disconnected" with the manual "Reconnect" button
  and nothing more is tried; with the device kept down there are 8 attempts (1, 2, 3, 5, 5, 10, 10, 15 s apart) and then
  the error with the last reason. A device that has just restarted may answer the first login with "connection refused":
  the page keeps counting down and connects on a later attempt instead of stopping. With "Remember password" on, the password is saved once, not again after a reconnect;
  with a saved password every attempt logs `rustdesk.saved_password_used`; change the device password while it is down
  → the reconnect stops at the password prompt. View only and the clipboard switch keep their values; the device ending
  the session with a reason, or **Disconnect**, does not reconnect; localStorage and sessionStorage hold no password or
  hash. While the device is down, change its IP allowlist so it leaves out the jt-ipam server (or make it accept
  connections only while its main window is open) → the reconnect gets "Your ip is blocked by the peer" (or "The main
  window is not open"), stops at once and shows the reason instead of trying 8 times. On a real Linux device at the GDM
  login screen, log in through the web session → it comes back on the new desktop session without a click
- [ ] **Session switches on the device** (spec appendix G.5; frontend `src/rdweb/__tests__/sessionSwitch.test.ts`):
  every reconnect's LoginRequest carries the same `session_id` and `my_name` as the first connection, and no
  `close_reason` is sent before a reconnect (only **Disconnect** sends one); Windows logoff, user switch and an RDP
  session taking the console reconnect by themselves, while lock, Ctrl+Alt+Del and UAC do not drop the session; on Linux
  log out and switch users with GDM and with another display manager (LightDM or SDDM), X11 and Wayland; on macOS log in
  from the login window. A device with a one-time password that restarts → the reconnect stops at the password prompt
  with the one-time password hint; connect with an empty password while the device is at its login screen → "The device
  is at its login screen" and the password works on the same connection; a Wayland login screen → the explanation with
  the documentation link as plain text and no retries; after logging in to a Wayland desktop the "choose the screen to
  share" message box appears and the page keeps waiting until someone at the device chooses
- [ ] **Windows session picker** (spec appendix G.6): an installed Windows device with a console and an RDP session
  (sharing RDP sessions on) → the page lists both with the current one marked; keep the current one → the picture
  appears; pick the other → the device switches, the page reconnects by itself and shows that session without asking
  again; with only one session nothing is asked and the picture appears; zh / en / ja once
- [ ] **Linux device without a desktop** (spec appendix G.7; RustDesk 1.4.x with "allow headless" on, nobody logged in):
  the page asks for the OS username and password (plus the RustDesk password when the device says it is empty or wrong);
  the second login goes over the same connection (one `rustdesk.web_session_open`) and the desktop appears within about
  10 seconds; a wrong OS password ("Desktop xsession failed") asks again; another user already logged in ends with an
  explanation; the OS username and password appear in no browser storage, log or audit entry, and a later reconnect
  does not send them again; three wrong RustDesk passwords on this path ("password wrong", mixed with "Wrong Password"
  or not) hit the same per-user limit (`tests/test_rustdesk_web_console.py`), while the "password empty" prompt does not
  count
- [ ] **Clipboard** (spec appendix F; frontend `src/rdweb/__tests__/clipboard.test.ts`, `clipboardSession.test.ts`): the
  toolbar "Clipboard" switch is on by default, off and greyed out in view only. On the device run
  `docker exec rdtest-client sh -c 'echo -n peer-123 | DISPLAY=:0 xclip -selection clipboard'` → the browser clipboard
  holds `peer-123` (with the tab in the background, the "copied something" prompt appears and one click copies it); copy
  text in the browser, click the picture, press Ctrl+V in an application on the device → it pastes the new text, not the
  old one (`xclip -o -selection clipboard` on the device shows it; on a Mac, Cmd+V does the same); **Send text** changes
  the device clipboard without pressing a key; more than 1 MB in either direction is refused with a message; switch it
  off → neither direction syncs and Ctrl+V pastes the device's own clipboard; switch it back on → syncing resumes.
  Repeat once against a real Windows device (copy and paste in Notepad on both sides)
- [ ] **Multiple displays and quality** (spec appendices H and I; frontend `src/rdweb/__tests__/displays.test.ts`,
  `quality.test.ts`, `src/components/__tests__/rustdeskDisplayQuality.test.ts`): with one display and no
  resolution to choose there is no **Displays** menu; a single physical display that reports resolutions shows the
  menu with only the **Resolution** submenu, and picking one changes the device's resolution. Give the test target a second display (or use a real two-monitor device): the menu lists both with
  their sizes and marks the current and the primary one; switching shows the other display, and clicking into an xterm
  on the second display and typing works where you click; unplug the display you are viewing → a notice and back to the
  primary display; change the resolution of the shown display → the picture follows, no switch; restart the device
  container while on display 2 → after the automatic reconnect you are on display 2 again. The **Resolution** submenu
  is missing in view only. The **performance line** (latency, bitrate, frames, codec) is hidden by default; ticking
  "Show performance" in the quality menu shows it, clicking again hides it, and it survives a reload
  (`jt-ipam.rdweb.show_stats`). **Quality**: with the performance line on, Low and Best change the bitrate; with a
  15 fps limit the decoded frames per second stay at 15 or below; the codec list shows only codecs both sides support,
  and switching the codec keeps the picture; reload the page → the three choices are kept, and browser storage holds only
  `jt-ipam.rdweb.quality` (level, custom value, fps, codec) and `jt-ipam.rdweb.show_stats`
- [ ] **Security**: one character wrong in the public key stored in jt-ipam → "public key does not match the server"; hbbs
  started with `-k <public key string>` (does not sign the device identity) → refused, no downgrade, and the
  message points to the key file (`KEY=_`); replayed, expired
  (30 seconds) or other-IP tickets are refused; without remote console rights, with RustDesk connections off on the IP or
  with web connections off on the server there is no button and no ticket
- [ ] **Audit and resources**: every session has `rustdesk.web_session_open` / `rustdesk.web_session_close` (RustDesk ID,
  transport, relay name from hbbs, relay address actually used, end reason, login results reported by the browser); the
  device's own connection audit (`my_name` is "user (jt-ipam)") matches; more than 3 sessions per user or 20 per server
  are refused
- [ ] **Install and upgrade**: a fresh install's nginx console WebSocket location includes `rustdesk`; upgrading an older site
  with `jt-ipam.sh upgrade` rewrites the location to include `rustdesk` and `jt-ipam.sh doctor` shows "nginx forwards
  WebSocket for all consoles"; after migration 0180 every server has web connections off
- [ ] **Device type from IPAM facts**: an IP whose device record is a firewall/router/switch/AP shows that type even when
  Identify guesses otherwise; a LibreNMS-classified firewall, printer, AP, NAS or switch likewise; a Linux machine with a
  Wazuh/RustDesk/OCS agent and xrdp is a server, not Windows; a VM never becomes a switch/printer/camera; a DHCP address
  whose old VM or Wazuh agent belonged to another machine (different MAC, agent silent > 7 days) is not influenced by
  them; the Identify page shows "The IP record uses: … (from …)". An iPhone (port 62078) is a phone/tablet; the Identify
  summary shows the device vendor and the NIC vendor on separate rows.
- [ ] **Device type knowledge tables** (`tests/test_device_kind_knowledge.py`, `tests/test_device_kind_generic.py`,
  `tests/test_ip_identify_regex_safety.py`): run Identify on every kind of device the site has (camera, IP phone, UPS
  card, NAS, firewall, AP, printer, ESXi or PVE host, BMC, PLC or building controller, streaming player, phone) and check
  the type and its evidence line. A Linux server with node_exporter (9100), CUPS (631), Plex or video management software
  such as Blue Iris stays a server. A NIC vendor shown as SonoSite, Carlo Gavazzi or Boser gives no type, while
  `ZhejiangDahu`, `AmericanPowe` and `SonyInteract` give camera, specialized and media; a phone with a randomized MAC gets
  no type from its vendor. Host names: `DESKTOP-XXXXXXX` gives Windows, `nvr-server` and `camera-archive-01` give no
  device type, `*.cam.ac.uk` is not a camera, and an address named `printer-2f` that a Windows PC now uses shows Windows.
  After the scan agents update to 1.17.2, the identify result carries `method`/`devicetype` per port, and a Linux host
  whose 445 nmap only guessed from the port table (Samba) is not Windows.
- [ ] **Device type, second-round rules** (the "second adversarial round" tests in `tests/test_ip_identify.py`,
  `tests/test_device_kind_identify.py`): Identify on a router or IoT gateway that only serves a web page and no SSH
  gives unknown (not server); a Linux host with OpenSSH or a Debian/Ubuntu string is still a server; a device running
  BusyBox is not a server. An AP with 3517 open (VigorAP) is a wireless AP, and a DrayTek NIC without a model is not a
  router. A Samba AD DC (135 says Microsoft Windows RPC, OS is Debian) is a server, not Windows; a Windows desktop
  running Docker Desktop stays Windows. A bare-metal Proxmox Mail Gateway or Datacenter Manager is not a hypervisor. A
  Tapo plug (Server header SHIP 2.0) is specialized and a Tapo camera is a camera; an Apple TV is media and an iPhone is
  mobile. A Debian VM's OS shows Debian Linux 11/12/13 instead of Linux 2.6.32. The host name `P105` gives specialized
  only on a TP-Link NIC, and `voip-router-2` and `smart-gw` give no type.
- [ ] **Local RustDesk client audit** (`tests/test_rustdesk_local_open.py`): clicking "Open in the RustDesk client software on this computer" (the arrow item or the "Local" button) adds an audit entry `rustdesk.local_client_open`, and an admin's Investigate lists it under recent remote sessions; an account without RustDesk rights gets 403 from the endpoint.
- [ ] **RustDesk split button**: with the web connection available the IP page has one RustDesk button whose arrow offers
  "Open in the RustDesk client software on this computer"; hovering the arrow and that item shows a tooltip; without it,
  the single local-app button with the "Local" badge.
- [ ] **Page kept on back**: on page 2 of a subnet's IP list (and of the IP address list), open an IP and go back: still
  page 2, with the page size kept.
- [ ] **Wrong Key on a client**: set a client's RustDesk Key wrong (change the case of one letter) and try the web
  connection: within about 10 seconds the RustDesk page shows "Wrong Key 1" on the server row (click lists only that
  device), the device list marks it, the IP page and device page explain it, and the web connection fails with the
  wrong-Key message without restarting from rendezvous. Fix the Key and connect again: the mark goes away. Several clients
  behind one NAT IP are not marked. **Test** shows the hbbr/hbbs log check; with `JT_RD_LOG_DIR` pointing at a missing
  directory it fails and everything else keeps working. Rotating the log (`logrotate -f`) does not lose or repeat
  events. Agent 1.0.0 polling an upgraded server still works and updates itself.
- [ ] **Delete old registrations** (`tests/test_rustdesk_peer_delete.py`, `tests/test_agent_rustdesk_delete.py`,
  `tests/test_rustdesk_installer.py`, `e2e/rustdesk-peer-delete.spec.ts`; a real RustDesk Server, e.g. `scripts/rustdesk-test-target`): off by default, the
  Devices tab has no tick column and "Delete old registrations" is greyed out with a tooltip that asks to switch the
  setting on. With "Allow deleting old registrations" on but the agent not installed with `--allow-delete`, the tooltip
  shows the agent's reason (not enabled on this host...), Test shows "Delete old registrations (write access)" as a
  passing read-only check, and `systemctl cat jt-ipam-rustdesk-agent` still has `ReadOnlyPaths=/var/lib/rustdesk-server`.
  The install dialog's command gains `JT_RD_ALLOW_DELETE=1` with an explanation; on the RustDesk host run
  `... | sudo env JT_RD_ALLOW_DELETE=1 bash` (no URL or key) → the config keeps its URL and key and gains
  `JT_RD_ALLOW_DELETE=1`, the unit has `ReadWritePaths=... /var/lib/rustdesk-server` and
  `InaccessiblePaths=-/var/lib/rustdesk-server/id_ed25519` (the private key cannot be read from the service namespace
  with `nsenter`), other hardening unchanged; within about 10 s the button can be used. Filter "Never seen online" →
  "Tick all matching offline devices" → delete: the dialog states the count, that online devices are skipped and that a
  client registers again by itself; within about 10 s "N deleted" appears, the list and device count update,
  `sqlite3 db_v2.sqlite3 "select count(*) from peer"` drops by N and no other table changes; bring one ticked device
  online first → it is "Skipped (online)"; lock the database or stop hbbs so the online check fails → "Failed" with the
  reason and nothing deleted. A deleted client that comes back online reappears (one hbbs has seen since its last start
  needs an hbbs restart first). "Deletion log" lists every result and who asked; the audit log has
  `rustdesk.peer_delete_requested` (who, which IDs) and `rustdesk.peer_deleted`. Turning the setting off makes waiting
  requests "Cancelled"; an agent offline for over a day makes them "Failed" (expired). Re-running the install command
  without the flag makes the unit read-only again. With two or more servers the online filter changes only itself, not
  the mapping status filter. Check zh / en / ja once.
- [ ] **Password field**: Chrome with a saved jt-ipam login does not fill the RustDesk password field.
- [ ] **Remember password** (appendix D; `tests/test_rustdesk_saved_password.py`, `src/rdweb/__tests__/session.test.ts`,
  `e2e/rustdesk-web.spec.ts` against the test target, form states in `e2e/rustdesk.spec.ts`; the form is laid out like
  the VNC one, compare the two side by side at desktop and phone width): turn on the "Remember password" switch,
  type a wrong password and then the right one → nothing is stored after the wrong one, and once the login succeeds the
  vault holds exactly one `rustdesk` entry for that IP; open the connection again → the "Saved password" drop-down has
  it selected, there is no password field or "Remember password" row, and it connects without typing (audit
  `rustdesk.saved_password_used`, the credential's last-used time updates); change the device's password → the page says the saved password no longer works, does not retry it, offers
  "Delete saved password", and the new password typed with "Remember password" replaces the old entry (still one
  entry); picking "Use a different password (enter it below)" or clearing the drop-down shows the password field again,
  and the delete button next to the drop-down removes the saved entry; localStorage and sessionStorage hold
  no password or hash; backend logs and audit contain no password or hash; after the last entry is deleted (or when
  nothing was ever saved) the whole "Saved password" row is gone (the same for the SSH, SFTP, RDP, VNC, noVNC and BMC
  "Saved credentials" row)
- [ ] **Same device, other IP**: on a device with two IPs where RustDesk maps to one, editing the other IP shows a
  disabled "Enable RustDesk connection" with the mapped IP as a link (RustDesk ID, enabled or not); an IP that only shares
  the hostname shows nothing; a user who cannot see the other subnet sees nothing.
- [ ] **Relay refused**: a peer whose RustDesk Key differs from the server's fails the web connection with the relay
  timeout message that names the Key as the most common cause (hbbr logs `Relay authentication failed ... invalid key`).
- [ ] **UI**: the new fields in the RustDesk server form (web connection, hbbs address, relay address, transport) in zh /
  en / ja; the Connections page has a RustDesk button and a "RustDesk" type filter; with web connections off the IP page
  keeps the original button with the "Local" badge
- [ ] **Send text, Type it** (appendix F.4; `src/rdweb/__tests__/typeText.test.ts`): in the test target's xterm type a
  command with capitals, symbols and a line break and it runs; text with Chinese is refused with the clipboard hint;
  2001 characters are refused; Stop during a long text leaves no stuck key; the button is disabled in view-only mode
  and while the device has turned off control; zh / en / ja each once.
- [ ] **File transfer** (appendix J; `tests/test_rustdesk_web_files.py`, `src/rdweb/__tests__/files.test.ts`,
  `fileSession.test.ts`, `fileSave.test.ts`): with **Allow web file transfer** off the RustDesk ▾ menu on the IP page has
  no **File transfer** and a `kind: "file"` ticket is refused (`rd_file_disabled`); turn it on (try the limits too) and
  the entry opens a new tab; log in and the home folder is listed; on a Windows device going up from `C:\` lists the
  drives; show hidden files; download a file and compare its hash with the one on the device (in Chrome a file over
  200 MB asks where to save and is streamed); upload by picking and by dropping, then the same file again and the page
  asks to overwrite or skip (with "apply to the rest"); new folder, rename, delete a file and a folder with contents;
  cancel a running transfer; a second transfer waits in the queue; a file over the per-file limit is not sent; turn off
  file transfer on the device during the connection and the page ends with the explanation, and a device without the
  permission shows the translated reason at login; the audit log has `rustdesk.file_*` entries marked as reported by the
  browser, without any file contents; zh / en / ja each once.

- [ ] **Device import (issue #46, `e2e/device-import.spec.ts`, `tests/test_device_import.py`)**: a file exported from
  the list (once each in the zh / en / ja interface) imports back unchanged; the template with current devices imports
  back in update mode with zero errors; location / rack / unit by name, a rack alone implies its location, a rack
  name used in two locations asks for the location; existing devices are skipped / updated (blank never clears);
  rack-position overlaps within one file are refused; rows with errors are not written at all; the preview leaves
  nothing behind; every device is audited; .xlsx works; a value starting with = gets a leading quote in the template
  and loses it on the way back in

## 7c. Integration sync resilience: **applies to every integration, not just the one you changed**

Real devices are partially readable. A firewall answering "9 of 10 endpoints OK" is the
normal case, not an anomaly: firmware versions differ, and a read-only API account rarely
reaches every resource. What must never happen is one unreadable endpoint taking the rest
of the sync down with it (v0.5.195: an unreadable DHCP-lease path stopped ARP, policies,
NAT and address objects from syncing at all, while the UI showed a single error line).

- [ ] **Section isolation**: force one endpoint to fail (point it at a wrong path or revoke
  that one permission) and confirm every other section still syncs
- [ ] **Partial failure is visible**: the instance records what failed in `last_error`; a run
  with failures is never reported to the user as fully successful
- [ ] **No chain abort across instances**: one failing instance must not stop the sync round
  for the others (`session.rollback()` before writing `last_error`, or the next write explodes too)
- [ ] **Errors carry evidence**: a message like "response is not JSON" is useless in the field.
  Include status code, `content-type` and the first ~120 bytes, and name the likely cause
  (e.g. the device answered with its web UI, meaning that firmware lacks the endpoint or the
  API account cannot read it)
- [ ] **Connection test reflects reality**: the per-endpoint diagnostic shows the same result
  the sync would get, never a green tick for something the sync cannot read
- [ ] **What the upstream deleted must disappear** (2026-09-26 audit: hostnames from 16 sources and DNS
  records were never removed): delete one item upstream (DNS record, lease, VM, agent, host) and after
  one sync the IP's hostname and mirror rows must be gone. Hostnames always go through `HostnameRun`
  (`services/hostname_reports.py`): `report` what you see, `hold` entities whose data is uncertain this
  run, `finish(complete=…)` at the end; **complete must mean "this run really read everything"**, never
  a copy of the heartbeat's ok
- [ ] **Unreadable must not mean removed** (the opposite defect): make an endpoint time out / return 403
  for one run; existing hostnames, NAT, policies, VPN tunnels and DHCP ranges / reservations must stay
  untouched and `last_error` must say why. Only 404 (the feature does not exist there) counts as "read,
  nothing there". A VDOM / vsys list that fell back to a default is not a complete list; sections that
  replace a whole snapshot must not run
- [ ] **Instances of the same kind do not remove each other's data**: two firewalls of one vendor each
  report their own; when one stops, what the other still reports stays
- [ ] **Breaker**: make the API return an empty list for one run (permission revoked); hostnames must
  not be wiped, `last_error` must say why, and the rule-change sentinel must not report "all removed"
- [ ] **An unchanged field is not a manual edit**: change only the description in the IP edit form and
  save; neither the hostname source nor the MAC source may become manual
- [ ] **An unknown-source MAC does not freeze** (2026-10-05: a DHCP address moved to another laptop and the IP page kept
  showing the previous Apple vendor): set an IP's `mac_source` to NULL and its MAC to some other value, wait for a scan
  agent or firewall ARP sync; the MAC must change to the real one with a "MAC changed" entry; when the value was already
  right only the source is recorded, with no change entry
- [ ] **A device change clears the previous device's names** (`test_mac_change_forgets_names_reported_by_the_previous_device`):
  with NetBIOS/mDNS names on an IP, make its MAC change to another device; NetBIOS, mDNS, Wazuh, OCS and RustDesk vanish
  from "Hostname sources" while manual, DNS, firewall and DHCP stay; the same MAC reported again clears nothing; the
  first MAC fill clears nothing
- [ ] **Manual hostname is removable** (`e2e/hostname-source-clear.spec.ts`): "Manual" under "Hostname sources" on the IP
  detail has an x; it asks first, then the hostname is recomputed in precedence order and an audit entry is written;
  other sources have no x; a read-only account sees no x; hovering each source shows "Last reported: <time>"
- [ ] **Several MACs for one IP do not flip** (`test_several_devices_disagreeing_on_a_mac_decide_once_per_sync`,
  `test_mac_run_decides_once_whatever_the_report_order`, `test_two_macs_for_one_ip_in_a_batch_do_not_flip`): three LibreNMS
  devices report A and one reports B -> A, and three rounds log nothing more; a tie that includes the current MAC changes
  nothing; a tie without it changes nothing; two Proxmox guests on one IP never flip whatever the report order; after syncs
  `ip_change_log` must not show a "MAC changed" for the same IP every round
- [ ] **One link button in the device field** (`e2e/device-link-single-button.spec.ts`): with the hostname equal to an
  existing device's name only one "Link ..." button shows; changing the hostname (unsaved) to another device's name shows
  that device's button instead
- [ ] **RustDesk toolbar**: at about 1,370px wide with a Windows peer (longer status pill) all buttons stay on the first
  line and latency/bitrate/fps/codec sit alone on the second line
- [ ] **RustDesk Windows portable peers and elevation** (`rdweb/__tests__/elevation.test.ts`,
  `components/__tests__/rustdeskElevation.test.ts`, `test_rustdesk_web_elevation.py`): Linux and installed Windows peers
  show no elevation UI at all (`e2e/rustdesk-web.spec.ts` checks it too); a portable Windows peer (rustdesk-x.y.z-x86_64.exe
  run directly, not installed) shows "Portable"; open a program that needs administrator rights there and accept UAC, and
  the web shows the elevated-foreground notice; "Request elevation -> confirmed on the peer" plus a UAC click there makes
  that program usable and the tag reads "Portable, elevated"; "with an administrator account" succeeds without touching
  the peer; a wrong password shows an error; the audit has `rustdesk.elevation_request` (requested and ok/error) without
  credentials
- [ ] **Dark operating system with jt-ipam light (and the reverse)** (`e2e/rustdesk-web.spec.ts` emulates a dark OS): the
  note at the bottom of the RustDesk web connection's "Quality" menu is readable, not a blank area; dropdowns, scrollbars
  and inputs elsewhere follow the jt-ipam theme
- [ ] **Connected time** (`components/__tests__/connElapsed.test.ts`, `e2e/rustdesk-web.spec.ts`): SSH, SFTP, RDP, VNC, PVE,
  BMC, RustDesk desktop and file transfer show a running hours:minutes:seconds timer in the status bar once connected, with
  the start time on hover; it stops on disconnect, restarts from zero on a new connection, and RustDesk auto-reconnect
  does not reset it
- [ ] **Audit records connection length** (`test_console_session_duration.py`, `test_investigate_sections.py`): every
  console's close audit has `duration_seconds` (SFTP sessions that never opened record none); Investigate's recent remote
  sessions show "connected hh:mm:ss", two parallel sessions by one user pair in order, unfinished ones show nothing
- [ ] **RustDesk online state does not flap** (`test_report_does_not_flip_a_heartbeating_device_offline`): a client
  with an API server (heartbeat every 15 s) stays online across several full reports; after the client is closed it
  turns offline at the next full report once heartbeats have stopped for over 45 seconds
- [ ] **Device ports follow LibreNMS** (2026-09-27: a pulled dual-port NIC and USB NICs stayed in the
  list although LibreNMS had marked them deleted): pull a NIC / unplug a USB NIC, let LibreNMS rediscover,
  then sync or press "Import from source", and its ports disappear from Ports / cabling; ports you created
  yourself, cabled ports and pass-through-mapped ports stay; a failed read or an empty port list removes
  nothing. Docker `veth…` interfaces are never imported (`tests/test_device_ports_reconcile.py`)
- [ ] **Cannot connect = failed, never "succeeded, 0 records"** (#44): point an integration at an unreachable
  host and at a wrong token; the task ends as failed with the last error (Proxmox with every node failing,
  LibreNMS, AdGuard…) (`tests/test_sync_total_failure_is_failure.py`)
- [ ] **The same key twice in one response** (#43): an upstream that repeats a row (the same MAC / port / VLAN)
  must be merged in memory, not hit a unique constraint; and a task whose database session broke must still
  end as "failed" with the error, **never stay "running"** (the final status is written with a clean session)
  (`tests/test_librenms_fdb_duplicates.py`)

## 7d. Probes run from a scan agent: **whenever the probe queue or the agent changes**

Letting the server hand work to an agent turns that agent into something that runs network
probes on request inside a customer network. The feature is only as safe as its narrowest check.

- [ ] **Kind allowlist**: anything outside ping / tcp / traceroute / rdns / identify is refused, by the
  backend *and independently by the agent* (a compromised backend must not be able to widen it)
- [ ] **Target validation**: shell metacharacters, command substitution and argument injection
  (`-oProxyCommand=…`) are rejected; arguments are always passed as a list, never through a shell
- [ ] **Limits hold**: target count, port count, per-agent pending jobs, and clamped
  count/timeout values
- [ ] **Ownership**: an agent can only finish a job it claimed itself
- [ ] **Expiry**: with the agent stopped, a queued job expires instead of running late when the
  agent returns; a probe answering minutes after the question is worse than no answer
- [ ] **Round trip on a real agent**: create → claim → execute → report → read result, and the
  UI states which agent produced the output
- [ ] **"Probe" on the IP detail page (identify)**:
  - only admins see the button; a read-only account calling `POST/GET /addresses/{id}/identify`
    gets 403
  - the target can only be that IP record's own address: the tools page's agent probe refuses
    `identify`; the agent itself refuses host names, multiple targets and networks
  - it runs on the scan agent assigned to the subnet; a subnet without one says so (not a blank
    failure)
  - one probe per IP at a time; every start is audited (action=identify)
  - the NSE script list is fixed inside the agent (read-only: banner / HTTP title / TLS
    certificate / SSH host key / SMB / RDP) and nothing the backend sends can change it; no
    industrial-protocol ports
  - run it once against a real PVE host: the type is hypervisor, 8006 is in the port list, and
    the names contain neither the certificate issuer nor wildcard names; an agent without nmap
    shows the "names only" notice
- [ ] **Probe by address (Probe in the anomaly lists, for an address IPAM has no record of)**
  (`e2e/anomaly-identify-cols-tabs.spec.ts`):
  - the address must be inside a managed subnet (the most specific one) and runs on that subnet's agent;
    an address outside every managed subnet gets `identify_not_managed`, a network/broadcast address
    `identify_bad_target`, and no job is created
  - overlapping subnets with the same CIDR handled by different agents → `identify_ambiguous`; never
    pick one and scan
  - a registered address goes to that record's probe page (same history); duplicate records must not be
    labelled "not in IPAM"
  - the task row carries the address, the completion notification links back to `/identify/ip/<address>`,
    the audit entry carries the subnet
- [ ] **Probe + Recog fingerprints** (`backend/tests/test_recog.py`, `e2e/ip-identify.spec.ts`,
  `e2e/recog-admin.spec.ts`):
  - import: every fingerprint must pass its own examples or it is dropped (about 5 in 3.2.0); only
    `xml/*.xml` is read from the zip, XXE is blocked, and a suspiciously small release (under 1,000
    fingerprints) never replaces the installed one
  - summary: the OpenSSH comment gives the distribution, a device default certificate gives type / vendor /
    model, "assert nothing" entries are ignored, ports nmap already named are not listed twice, and a default
    certificate's name is not listed as a host name; without Recog the summary is exactly as before and the
    page says it is not installed
  - on real data: re-summarise existing prod probe results with and without Recog; no type may get worse
    (NAS, PVE, mail host, IPMI)
  - **Admin → Recog fingerprints** (like the OUI database page): release, fingerprint count, install and last
    check times, per-file fingerprint counts (filterable); "Check for updates now" is audited
    (target=recog_db_update). Version info only lists the Recog release among the optional dependencies, with
    the name linking to this page; there is **no** update button on Version info
  - the optional dependencies also list **oui** (last update date; an empty OUI table shows "missing" in red and joins
    the warning) and **geoip** (without a MaxMind account it shows "not configured" and is not in the warning; a local
    database shows the file date, an account alone shows web service); the names link to the OUI page and System settings
  - a failed update (GitHub unreachable) leaves the installed release alone and shows the error on the Recog page;
    the system diagnostics warn after three weeks without a successful check

## 7d2. Scan agent load: **whenever the agent's scan loop, its reports or the load evaluation change**

- [ ] **Liveness is never held up by heavy probes**: the agent reports each subnet as soon as its liveness pass
  is done; reverse DNS / NetBIOS / mDNS / OS fingerprinting run in the background and names do not wait for
  the OS fingerprint. On a real agent, `journalctl -u jt-ipam-scan-agent` shows each cycle's "probes=… alive=…"
  within seconds to tens of seconds, with `[heavy]` running separately
- [ ] Background results are **not evidence of being online** (`liveness=false`): they do not touch last-seen
  and never create IPs
- [ ] Cycle statistics land in `scan_agents.last_cycle` and `scan_agent_cycles` (kept 7 days); the Load column
  and panel on the Scan agents page show them
- [ ] Overload alerts: only after 3 consecutive cycles, sent once, plus once on recovery; the suggestions are
  actionable (which subnets to move, which subnet is unusually slow, which one is truncated)
- [ ] No automatic re-assignment: "Move to another agent" in the panel is an admin's click, with a reminder that
  the agent must be on the same network segment
- [ ] **Subnets over 4,096 addresses are scanned in rotating chunks**: assign a /19; each cycle covers the next
  chunk and wraps around (it used to scan only the first chunk forever); a full pass slower than the online
  threshold counts as overload with a suggestion to split the subnet (`tests/test_agent_scan_split.py`)

## 7e. Audit chain anchoring: **whenever audit writes, anchoring or the sync schedule change**

What this section tests is the thing the chain itself cannot catch. Verifying the chain is not enough.

- [ ] **Tail truncation**: delete the last few rows after anchoring → must report
  `anchored_row_missing`; `verify_chain` alone reports "intact" for the same case, which is
  precisely why anchoring exists
- [ ] **Content tampering**: change the anchored row's hash → `anchored_hash_changed`
- [ ] **Shrinking count**: delete any middle row → `count_shrank` or `chain_broken`
- [ ] **Incremental**: the second verification resumes from the last anchor rather than
  rewalking the whole chain
- [ ] **Anchor file**: appended line by line (never rewritten), mode 0600, one corrupt line does
  not break reading; the same record also goes to journald (a copy survives file deletion)
- [ ] **Alerting**: on failure every admin gets a severity=error notification naming which case it was

## 7f. Zabbix integration: **whenever the Zabbix sync or coverage gap changes**

- [ ] **Three URL forms**: `https://host`, `https://host/zabbix` and a full `api_jsonrpc.php` all connect
- [ ] **Both auth modes**: API token and username/password each tested; the read response carries no secret
- [ ] **Stamps existing addresses only**: a host in Zabbix that IPAM does not know must not create an IP
- [ ] **Scope**: with `scope_subnet_ids` set, the same IP in an overlapping range is not stamped onto
  another tenant's address; queries use `limit(1)` (`scalar_one_or_none` aborts the whole round)
- [ ] **Hostname convergence**: two Zabbix hosts pointing at one IP must not overwrite each other every
  round (the change log must not fill up)
- [ ] **Coverage gap**: asking with a subnet scope answers only for those subnets; an empty scope
  returns empty rather than falling back to global

## 7g. Evidence contract: **whenever a source is added or changed**

What this section guards: **a new source must answer whether its evidence expires**.
The cost of not having that gate has already been paid: ARP was treated as timestamped
evidence, and a machine powered off for weeks showed 52 days of green.

- [ ] **Registered**: the new source declares its tier and `aging` in `services/evidence.py`;
  `pytest tests/test_evidence_contract.py` is green (the guard rejects unregistered sources)
- [ ] **Tier is right**: passively learned mappings (ARP/FDB/DNS/DHCP/virtualisation config)
  are `learned` with `aging=False`; only active probes and third-party monitoring may age
- [ ] **No string matching for source semantics**: no `"scanner" in status` style checks
  remain; ask `evidence.is_aging()`, so a new source cannot fall into the loosest branch
- [ ] **Liveness settings**: the options and defaults are derived from the contract;
  a non-expiring source is **not** selected by default
- [ ] **Per-vendor evidence is labelled honestly**: a firewall's ARP table, VPN sessions and
  DHCP leases land in `ip_addresses.arp_seen` as `arp:<vendor>` / `vpn:<vendor>` /
  `lease:<vendor>`, **never** in `last_seen_scanner`. A site with no scan agent must never
  show "online (scanner)". `pytest tests/test_liveness_sources.py` green
- [ ] **Upgrade keeps the previous verdict**: firewall ARP was counted before the split
  (it was written as scanner evidence), so `arp:<vendor>` stays trusted by default;
  otherwise a firewall-only site goes entirely offline on upgrade. Leases do **not**:
  a lease can outlive the machine by days
- [ ] **Static ARP entries are skipped**: a permanent/static entry never ages out, so
  stamping it would mean "this host is alive forever"
- [ ] **Ghost-IP and ARP-only detection follow**: an address only a firewall can see is
  neither reported as a ghost nor as "ARP only"
- [ ] **Availability bar**: days backed only by ARP are grey, not green; carrying a state
  forward requires the source that state claims to still exist
- [ ] **Precedence**: all five attributes (hostname/MAC/OS/device name/model) take effect
  immediately after a change and disabled sources really are excluded;
  `pytest -k "precedence or hostname or arp"` green
- [ ] ⚠️ **Cache**: precedence uses a module-level 60s cache cleared between tests by
  `conftest`'s `bust_all()`. If the cache moves, **verify that fixture still clears it**;
  it once failed silently and tests leaked settings into each other

## 7h. IP lifecycle and cooldown: **whenever release, allocation or the cooldown setting change**

- [ ] **Release starts a cooldown**: after deleting an address it appears under
  `/addresses/cooldowns/{subnet_id}` with the previous hostname and MAC
- [ ] **The record survives deletion** (releasing an address in practice means deleting it)
- [ ] **Allocation skips it**: neither the free-address list nor automatic allocation offers it
- [ ] **Manual creation is refused**: recreating the address returns 409 with a readable
  message including the end date and previous hostname, **not** `[object Object]`
- [ ] **Early clear**: after clearing, the address can be used again, but the record remains
  with who cleared it, when and why (recorded, not erased)
- [ ] **Disabled**: setting 0 days restores the previous behaviour and writes no record
- [ ] **Purge**: the sync round removes long-expired records but **keeps recently expired ones**
  (the days right after expiry are exactly when someone asks who had the address)

## 7i. Event rules: **whenever rules, conditions or event dispatch change**

- [ ] **Conditions are not expressions**: confirm nothing is evaluated; regular expressions
  are **unsupported** (ReDoS)
- [ ] **An unknown operator never passes** (passing is the dangerous default)
- [ ] **Field paths walk data only**: `data.x.y` must not reach attributes
- [ ] **AND semantics**: every condition must hold; no conditions means the event name decides
- [ ] **A broken rule does not stop the others**: a malformed rule is flagged and skipped while
  the remaining rules and the normal webhook dispatch continue (**never silently inert**)
- [ ] **Dry run has no side effects**: it reports what would match without sending anything
- [ ] **The webhook action uses the same path**: signing and the SSRF guard cannot be bypassed

## 7j. Topology access layer (FDB): **whenever FDB inference or the topology map changes**

> FDB says "this MAC appeared on this switch port". Turning that into lines has two classic traps,
> and both of them draw a map that is confidently wrong rather than visibly empty.

- [ ] Access edges appear for hosts on ports carrying a single MAC, labelled with the port name.
- [ ] A port carrying more MACs than the threshold (an uplink/trunk) produces **no** access edges:
  the hosts beyond it are not drawn as plugged into that port.
- [ ] A port with several known hosts draws **dashed** edges (behind this port), not solid ones.
  Clicking such an edge shows "Directly attached: No" and the MAC count on the port.
- [ ] Two switches are joined only when each sees the other and the MAC sets behind the two ports
  are disjoint. In an A-B-C chain, **A-C must not appear**.
- [ ] A MAC that maps to more than one device (overlapping subnets) produces no edge at all.
- [ ] **Device-to-subnet links from ARP**: a switch or router whose LibreNMS ARP table holds addresses of a
  subnet is linked to that (most specific) subnet with ARP as evidence, and the subnet filter keeps it. These
  links never appeared from v0.4.29 until 2026-09-30 because `arp_entries.device_id` (a LibreNMS device) was
  compared with jt-ipam device ids; it must go through `LibreNMSDevice.jt_ipam_device_id`
  (`tests/test_topology_arp.py`)
- [ ] Unchecking 存取層 (FDB) removes every l2/l2_uplink edge; the rest of the map is unaffected.
- [ ] A department account that cannot see one end of a link does not receive that edge (no edge may
  reference a node that is not in the graph).
- [ ] **View modes**: the toolbar offers automatic / centred on switches / access layer only / subnets
  only. Automatic centres on switches when the range has FDB data and falls back to the subnet layout
  when it does not; "centred on switches" falls back the same way rather than drawing a centre-less
  layout.
- [ ] **Access layer (FDB) starts unticked**, and the default view therefore matches the pre-0.5.213
  subnet-centred picture.
- [ ] In the switch-centred layout the switches sit in the middle, their hosts above them, and each
  subnet node directly below its switch with subnet-only devices beneath it.
- [ ] **"Access layer only" hides devices with no FDB data** rather than scattering them as orphan
  dots (check on an estate where most devices have none).
- [ ] **Virtual machines (unticked by default)**: ticking it places each VM directly beneath its
  host inside the host's subnet box; unticking removes them entirely. A VM with no identifiable
  host, or whose node name matches several devices, is not drawn. A VM already mapped to a device
  does not appear twice.
- [ ] **Audit coverage**: `pytest tests/test_audit_coverage.py` is green. A new data-changing
  endpoint must either record an audit entry or be added to `EXEMPT` with a stated reason,
  never silenced just to make the test pass.
- [ ] **Rack diagram embedding**: after enabling it and generating a token in system settings,
  turn on one rack's toggle, copy the URL and open it in a **logged-out** browser; the image
  must render. A wrong or empty token returns 401; a rack that is not shared and one that does
  not exist return an **identical** 404; regenerating the token invalidates old URLs at once.
- [ ] **Basis of each link**: clicking any link shows its "basis" (recorded by a person /
  reported by monitoring / learned passively / guessed from the name). With "recorded only"
  on, just the recorded links remain; IP-to-device links survive in the subnet view, while
  the access-layer view may empty entirely, which is correct, and means nothing was recorded.
## 7k. Logic between related fields: **whenever a field that determines another changes**

> The rule: **if it can be derived from a relation we already hold, do not ask again**.
> The only case worth blocking is "both were given and they contradict each other", because
> then one of them is wrong and picking for the user would be a guess. A customer hit this
> once: selecting a rack still demanded a location, while the rack dropdown already reads
> "location / rack".

- [ ] **Device rack → location**: saving with only a rack chosen works, and the stored location
  is the rack's. Choosing both inconsistently is blocked with an explanation. A rack with no
  location of its own neither blocks nor invents one. **Test both entry points** (device list
  and the edit dialog on the device page): when the same logic exists twice, usually only one
  copy gets fixed.
- [ ] **Subnet → section**: adding a subnet from within a section carries the section over.
- [ ] **IP → subnet**: adding an address from a subnet page carries the subnet over and it
  cannot be switched to a different one.
- [ ] **VM → cluster / physical host**: a VM's node comes from the virtualisation platform,
  not from a human picking one.
- [ ] **Rack U position → rack height**: position plus size must fit the rack, and half-U
  devices (left/right) must not overlap on the same U.
- [ ] **Scan settings → scan agent**: enabling scanning without naming an agent is blocked;
  that is genuinely missing information, not something derivable.
- [ ] **Certificate agent → certificate scope**: an agent can only fetch certificates in scope.
- [ ] Before adding any "if A is set then B is required" rule, ask: **can B be looked up from
  A?** If it can, derive it; block only when it cannot.
- [ ] **The dependency list matches what is declared**: `pytest tests/test_dependency_page.py`
  is green. Adding any third-party package means updating the version page's list as well as
  `pyproject.toml` / `package.json`; that page is what an upgrade or audit checks against, and
  a missing entry raises no error, it just quietly is not there.

### 7.x Consoles and file transfer (WebSocket): walk this whole class by hand

This group comes from field reports across v0.5.222-229. What they share is that **the symptom
is always the same ("connection lost") while the cause is different every time**, so testing the
happy path of "an upload succeeded" is not enough.

- [ ] **Drag a folder in** (a folder alone, and a folder mixed with files): **the whole folder and
  its nested contents** must arrive with the same structure, files dropped alongside must still
  upload, and the connection must **not** drop. Do NOT decide "is this a file?" by `size > 0`: macOS reports a folder as
  **256 bytes**, and that check is what corrupted the stream.
- [ ] **Drag several files at once**: every one must arrive intact; compare **byte count and md5**
  for each. Only one arriving, or one arriving at **0 bytes**, means the upload loop was
  interrupted partway.
- [ ] **Send a command mid-upload**: if the client declares a size and then sends the next command
  before finishing, the server must **end that upload, still execute the command, and keep the
  session usable**. The command must not be swallowed.
- [ ] **Declare a size and send nothing**: after a timeout the server must report an error and
  clean up the partial file; it must **never wait indefinitely**. A coroutine parked there holds
  both the WebSocket and the SSH connection, and the user sees "the whole page is unresponsive".
- [ ] **The session survives a failed upload**: one failure must not force a reconnect.
- [ ] **Reconnecting right after a failure works**: the ticket request must not time out. A long
  delay means the previous session is still stuck in the event loop.
- [ ] **An idle console must not be cut off**: open SSH / SFTP / RDP / VNC / noVNC and **leave it
  untouched for three minutes**, then use it again. A console without a heartbeat gets dropped by
  an intervening reverse proxy after **60 seconds without traffic** (a common default), and the
  user just sees an inexplicable "connection lost".
  BMC currently has **no** heartbeat (pure relay; injected data would corrupt SOL), a known gap.
- [ ] **Send a file large enough to take a while** through the console (say 50 MB, or 5 MB over a
  slow link): it must complete. **Do not test this on the LAN only**: uvicorn drops a connection
  when no pong arrives within 20s, and the pong queues behind the upload data, so only a genuinely
  slow uplink reproduces it (fixed in v0.5.231). Browser network throttling **will not** show it:
  it does not put the pong behind the upload.
- [ ] **Guard tests green**: `pytest tests/test_sftp_upload_stall.py tests/test_ws_wait_timeouts.py`.
  They hold the line on three things that break uploads outright: a receive loop with no timeout,
  `receive_bytes()` raising KeyError on a text frame, and forgetting to send `put_ready` after open.
- [ ] Whenever the upload block changes, **actually transfer a file**. The 0.5.225 rewrite dropped
  the `put_ready` line entirely, uploads never started, and the symptom was **identical** to the
  bug being fixed, easy to read as "still broken" rather than "newly broken". Neither type
  checking nor unit tests can see this.

## 8. Recent feature spot-checks

- [ ] **OCS card shows OCS's own hardware** (device detail): manufacturer / model / serial come from OCS,
  not from device fields another source filled (a Windows device created by LibreNMS once showed
  "windows / Intel x64"); motherboard and BIOS rows; a factory placeholder system serial ("0123456789")
  is replaced by the motherboard serial and marked "(motherboard)"; main components list CPU (cores /
  threads), memory (total + modules), physical disks (no zram / loop), GPUs (lspci and driver entries
  merged). Before the first sync after upgrading, the card says the details come with the next sync
  (`e2e/ocs-device-card.spec.ts`, `tests/test_ocs_hardware.py`)
- [ ] **IPs without an agent can be filtered by status** (Wazuh and OCS pages): the status column is the
  same dot as the IP list and the filter uses the same rule; the options only list statuses present;
  exporting the list fills subnet / section / unit / status (these were blank before)
  (`e2e/missing-agent-scope-filter.spec.ts`)
- [ ] **Ports / cabling: the MAC column shows the vendor** under the MAC, like the IP list
  (`e2e/device-ports-mac-vendor.spec.ts`)

- [ ] **Notification matrix** (Admin → 通知發送設定): toggle events × (in-app / email); save persists; events fire
  per matrix (IP request, cert expiring/deployed/drift, anomaly).
- [ ] **Cert distribution `files` profile**: writes cert files only, no reload/restart.
- [ ] **Anomaly page**: tabs, per-table column picker, `ip_address_id` hidden by default (MAC drift: see the next list).
- [ ] **Anomaly status lights** (`tests/test_anomaly_liveness.py`): every tab with IPs has a Status column (same light as
  the IP list, per-source times on hover, sortable, exported as text); in MAC drifts each IP of a row gets its own
  light. The status is computed when the page opens: bring an IP online after the run and re-enter, the light must
  change. Unauthorized IPs (no IPAM record) are judged from ARP observations and list the MACs ARP saw (vendor,
  locally administered/random, who saw it) and the last-seen time.
- [ ] **Anomaly detection keeps the last result**: run once → go elsewhere and come back, the result is shown without
  running again, "Last run" shows when it ran, scheduled runs are marked. On the Unauthorized IPs tab click
  Identify then Back → the same tab with the result still there (`?tab=` in the URL).
- [ ] **Unauthorized IPs on a large site** (`tests/test_anomaly_scope.py::test_large_arp_tables_are_not_sampled`): with more
  than 2,000 ARP addresses, unregistered ones beyond the first 2,000 are still found; over 1,000 results the tab shows
  "Showing the N most recently seen of M" and the list is ordered by last seen.
- [ ] **Online/offline source in the IP change history** (#49, `tests/test_liveness_flip_source.py`): on a site without
  LibreNMS, an IP going offline is recorded with source `system`, one coming back online with the source that saw it
  (`scanner`, `opnsense`, ...); the source filter lists every integration.
- [ ] **MCP client-config generator** (LLM/AI): button outputs Claude Desktop / opencode / mcpo / generic snippets.
- [ ] **LLM provider = OpenAI-compatible** (Admin → LLM/AI): switching to it shows the data-egress warning
  and the API-key field; the model dropdown repopulates from `/v1/models` (empty dropdown = the wrong path
  is being called); a base URL already ending in `/v1` is not doubled; chat and semantic search both work.
  Switching back to Ollama restores the `/api/tags` list. `select value from system_settings where key='llm'`
  must show **no plaintext key**, only `api_key_enc`; the settings page never returns the key itself.
- [ ] **Embedding dimension** (Admin → LLM/AI): the **Check dimension** button reports the model's actual
  dimension against the column size. After changing the embedding model, a reindex must report
  `failed: 0`, and if it reports `0 indexed` the failure count and reason must be visible, never a bare
  zero. A candidate model must also produce **different vectors for different Traditional Chinese
  descriptions** (English-only models collapse them and look fine while ranking at random).
- [ ] **Add address in a subnet**: the create form has a required IP field (issue #14).
- [ ] **Attach IPs by NIC MAC** (Admin → 系統設定): off by default on an existing install; **Preview**
  reports a count plus per-reason skips and changes nothing; enabling it attaches on the next sync round
  and writes one IP-change-log row per address with the match reason. Clear a device link by hand, then
  confirm the next round does **not** restore it (the rule that keeps the job from fighting the operator).

### Recent (v0.6.45–v0.6.55 and not yet released)

- [ ] **MAC drift = a port change on the same switch** (2026-09-30; `tests/test_mac_drift.py`,
  `e2e/mac-drift.spec.ts`): a MAC seen on two switches is the normal path, not a move; only a new port on the
  **same** switch within 24 h (previous port within 7 days) counts. The table shows switch, from port, to port and
  when; only physical device moves are anomalies (and notify). VM migrations (a known VM NIC or a Proxmox
  address), randomised MACs and moves between shared ports go into the collapsed **Reference** block with their
  category and never notify. Anomaly subnet scope and per-IP ignore ("mac_drifts") apply. On prod data, compare
  the counts before and after one LibreNMS FDB discovery (FDB timestamps refresh every 6 hours)
- [ ] **AI interpretation model** (Admin → LLM/AI → AI interpretation; `tests/test_ai_interpret_model.py`,
  `e2e/llm-interpret-model.spec.ts`): empty = the chat model and its context length (an upgraded site behaves
  exactly as before). Set a different model and run all three: AI triage of an unauthorised IP, "Ask AI to read
  this" in an IP investigation (streamed), and the AI reading of a firewall rule change; the LLM server's log shows
  the chosen model, and each result names it. The review (audit) model is a separate setting and stays unchanged;
  embedding models are disabled in the picker
- [ ] **IP conflicts without LibreNMS** (#41; `tests/test_anomaly_ip_conflicts.py`, `tests/test_ip_conflict_evidence.py`,
  `e2e/anomaly-ip-conflict.spec.ts`): with no LibreNMS configured, scan agents and firewall ARP tables (dynamic
  entries only) still produce conflicts, tied to their subnet so overlapping networks never conflict with each
  other; a MAC flipping between two addresses 3+ times in 24 h is flagged; the AI tool says "cannot be determined"
  when there is no evidence
- [ ] **A dual-NIC host is not an IP conflict** (`tests/test_ip_conflict_evidence.py`): when a host's two networks
  share a broadcast domain, both NICs answer ARP (ARP flux); two MACs that both belong to the same device (on its
  other IPs or its ports) are not reported, a third machine still is, and an IP with no device keeps the old rule.
  The periodic OS probe's "device type · vendor" comes from the MAC on the IP record, not the NIC that answered
- [ ] **Integration states are translated** (`src/utils/integrationStatus.test.ts`): the Wazuh card on device detail
  and the Wazuh / LibreNMS state in the Investigate report read "Active / Disconnected / Never connected", not
  `active` / `disconnected`; check all three languages
- [ ] **Investigate covers every integration** (`tests/test_investigate_sections.py`,
  `src/utils/__tests__/investigateSections.test.ts`): on a Windows host with OCS, RustDesk, Zabbix, a VM, DHCP and
  switch ports, Investigate shows Identity (type, the reason it was decided, NIC vendor, random MAC), Endpoint agents,
  Virtualization, DHCP, Where it is plugged in, Firewall evidence and Last seen by source; a bare record shows none of
  them (no empty headers). A department account gets no firewall objects/rules or DHCP offers; a global reader who is
  not admin gets those but no probe, anomalies, AI findings or console sessions. `win11-desk-01`, `win11-desk-01.` and
  `WIN11-DESK-01` from three sources are **not** a hostname conflict, `web01` vs `db01` is. All four exports (.md / .txt
  / .html / .csv) contain the new sections and the same conflicts as the screen; check all three languages
- [ ] **Anomaly filter** (`e2e/anomaly-filter.spec.ts`): one keyword (IP / hostname / MAC / details) filters every
  category and the tab counts read "matching / total"
- [ ] **Firewall rule rot** (`tests/test_fw_rule_rot.py`): OPNsense Anti-Lockout rules, port forwards to an alias
  and a WAN rule allowing only ICMP are **not** reported; any → any means every protocol and every port; the
  table has a Firewall column and the kind in words
- [ ] **PFX export password** (`e2e/cert-pfx-export.spec.ts`, `tests/test_certificates_api.py`): choosing PFX asks
  for a password twice (empty allowed, with a warning); the export is a POST with the password in the body; check
  the nginx access log and the browser history: **no password in any URL**; a GET carrying a password is refused;
  the file opens with that password on Windows
- [ ] **Address ranges (pools) inside a subnet** (#40; `tests/test_ip_ranges.py`, `e2e/subnet-ranges.spec.ts`):
  non-CIDR start–end ranges inside the subnet, no overlaps; size / used / next free (clicking it creates that IP);
  DHCP-pool ranges count as DHCP ranges everywhere (usage, "in a DHCP range", AI tools); audited; carried by
  system transfer. **Detected DHCP ranges appear automatically** marked "Auto" with their source, follow upstream
  (replaced, removed with the integration), never touch manual ranges, are skipped when the subnet is ambiguous or
  the range would overlap, cannot be edited by hand, and are not counted twice (`tests/test_ip_ranges_auto_dhcp.py`)
- [ ] **Rack kinds and drawing** (`tests/test_rack_more_kinds.py`, `e2e/rack-more-kinds.spec.ts`,
  `e2e/rack-side-channels.spec.ts`, `e2e/rack-room-align.spec.ts`): slotted angle steel shelving (presets, finish),
  IKEA KALLAX (square cells, frame thicker than dividers), LackRack (8U per table, 50 mm legs outlined); shelves use
  one scale for width and height; cable space on both sides from the outer width (465.1 mm hole spacing), top panel
  and base with thickness; a room row has one toolbar (front/rear, size slider, export) in both separate and merged
  layouts. **Compare screen, SVG / draw.io export and the embed image**: three implementations.
  At desktop width there must be **no** horizontal scrollbar under any rack (check with macOS set to always show
  scrollbars; KALLAX had one because its width was measured rounded)
- [ ] **IP detail page**: firewall rules, aliases and NAT rows click through to that vendor's page with only that
  entry shown (a banner offers "show all" and explains a missing entry); MikroTik address lists appear under
  "member of aliases" and `list:<name>` rules trace back to the IP (`tests/test_fw_lookup_aliases.py`,
  `e2e/ip-firewall-aliases.spec.ts`); the
  relation chart runs physical on the left, logical on the right, like the device page
- [ ] **OCS** (`tests/test_ocs_integration.py`, `tests/test_ocs_agent_tabs.py`, `e2e/ocs-agent-tabs.spec.ts`,
  `e2e/missing-agent-scope-filter.spec.ts`): the page has the Wazuh tabs (one agent row per computer); a subnet
  scope limits MAC matching (empty = global) and "IPs without an agent" lists only the union of the enabled
  integrations' scopes; the list filters by section / subnet / unit and export follows the filter; a container
  whose old agent (2.4.2 or earlier) marks every NIC virtual still matches its IP
- [ ] **Consoles**: when the remote host ends an RDP / VNC session the console says so, and an RDP session that
  ends before any screen lists the server-side causes (`tests/test_rdp_remote_ended.py`); the FreeRDP engine
  leaves no `xfreerdp` / `Xvfb` behind after 20 connect / disconnect cycles (`ps` before and after); where aardwolf
  cannot be installed the installer, the RDP/VNC error and system settings name the Python version and point to
  another engine; after "remember" on noVNC / BMC the saved-credential list shows the name, not a UUID
  (`e2e/novnc-saved-cred.spec.ts`); a PVE console login failure says why: wrong realm lists the realms, a
  rejected login names host and account, unreachable gives the cause (`tests/test_pve_login_errors.py`)
- [ ] **Reasoning models on OpenAI-compatible servers** (#36; `tests/test_llm_reasoning_control.py`): against
  llama.cpp with a thinking model (see the llama.cpp test target), AI audit / triage get an answer instead of
  spending the whole output limit thinking; a reply cut off while thinking says so instead of "(empty response)"
- [ ] **MCP over HTTP** (`tests/test_mcp_url_and_audit.py`): `POST /api/mcp` and `POST /api/mcp/` both reach MCP
  (the bare URL, the one the manual and the client-config generator give, used to return 405); a mutating
  tool called through `tools/call` writes an audit entry `mcp_tool_exec` (tool, summary, channel, source IP);
  configure a real MCP client (mcp-remote) from Admin → LLM/AI and run one read and one write
- [ ] **Audit log action column stays inside its cell**: filter a long name such as `rustdesk.peer_delete_requested`;
  the tag stays in the column (underscores visible), and narrowing the column turns it into "…" with the full name on hover
- [ ] **Audit entries name the actor** (`tests/test_audit_actor_recorded.py`): create a user, change a group's
  members and edit an OPNsense / Wazuh integration; each audit row has the acting admin (20 sites used to
  record nobody; `request.state.user_id` is now set by `get_current_user`)
- [ ] **AI tools are never looser than the REST data they read** (`tests/test_mcp_tools_match_rest_permissions.py`):
  as a wildcard-read non-admin, ask the AI chat for Wazuh agents, OCS computers, scan agents and certificates; each is
  refused, like the REST pages
- [ ] **Rack embed from another site**: put `<img src="https://<host>/api/v1/racks/<id>/embed.svg?token=…">` on a page
  served from a different origin; the image renders (the response carries `Cross-Origin-Resource-Policy:
  cross-origin` and no 30-day `Expires`); change the rack and reload, and the image changes
- [ ] **Behind nginx** (fresh install and upgraded site): `curl -k https://<host>/readyz` returns the backend's JSON
  (it used to be the SPA's index.html with 200) and turns 503 when PostgreSQL is stopped; repeated failed
  phpIPAM logins `POST /api/phpipam/<app_id>/user/` get 429 after the burst, with `Retry-After: 60` and a JSON
  body; after an upgrade the site has `location = /readyz`, the regex phpIPAM location and `location @rate_limited`
  (`patch_nginx_readyz_phpipam`, idempotent; check it in a real nginx container with mawk, as Debian has)
- [ ] **Thinking controls through an LLM gateway** (LiteLLM etc.; `tests/test_llm_reasoning_control.py`): when the
  server rejects one of `reasoning_effort` / `chat_template_kwargs` / `thinking_budget_tokens`, only the one the
  error names is dropped (LiteLLM rejects `thinking_budget_tokens` but turns `reasoning_effort: "none"` into
  Ollama's `think:false`), and the rejection is remembered per server and model so later requests do not fail
  first. With a real LiteLLM in front of a thinking model, an AI triage reply comes back in seconds, not minutes
- [ ] **Wazuh / OCS pages load fast on a large site** (`e2e/agent-tabs-lazy.spec.ts`): the "IPs without an
  agent" list (and Wazuh's full agent list) is fetched only when its tab is opened; the tab still shows the agent
  count on page load
- [ ] **"IPs without an agent" is paged on the server** (`tests/test_missing_agents_paged.py`,
  `src/composables/__tests__/useRemoteMissing.test.ts`, `e2e/missing-agent-scope-filter.spec.ts`): the tab fetches one
  page (not tens of MB); section / subnet / unit / status filters, the text filter and every column sort go to the
  backend and cover all gaps, not just the page on screen; picking a section narrows the subnet menu and clears a subnet
  from another section; the status light and the status filter agree with the IP list (same rule, compared in a test);
  export downloads everything that matches the filters; after an agent is installed the IP drops out on the next
  refresh. On the scale dataset (53k gaps) the first open takes about a second or two, paging well under one
- [ ] **AI chat can turn thinking off** (`tests/test_chat_thinking_setting.py`): Admin → LLM / AI has a "Let the model
  think before answering in AI chat" switch (on by default = old behaviour). Off: Ollama gets `think:false`, OpenAI-compatible
  servers (LiteLLM, vLLM, llama.cpp) get the thinking-off fields, official OpenAI gets none; a server that rejects one
  field still answers (only that field is dropped, and remembered). With a thinking model, turning it off makes the
  "thinking" stage disappear and replies come back noticeably sooner
- [ ] **Error responses keep their headers** (`tests/test_http_error_headers.py`): a `401` carries
  `WWW-Authenticate: Bearer`; a backend `429` carries `Retry-After` (60 for the rate limiter, 900 for the login lockout)
- [ ] **Device type from the periodic OS probe** (`tests/test_device_identity.py`, `tests/test_anomaly_identity_changes.py`,
  `e2e/recog-device-identity.spec.ts`): an agent 1.14.0 periodic OS result fills the IP's OS, device type and model
  (judged like the IP probe, Recog included); an old agent's one-line OS still works; a camera that turns into a
  Windows host shows under Anomaly → "Device type or OS changed" with old → new (unknown → known and A→B→A are not
  listed; Ignore this IP works); the IP list's Device type column (column picker) and the IP details show it; a
  topology device of unknown type takes its primary IP's kind. Run the agent's nmap path for real once (nmap in a
  container against a container target); unit tests mock nmap
- [ ] **An overruled fingerprint does not lend its type or vendor** (`tests/test_recog.py`, `tests/test_device_identity.py`):
  when Recog names a different OS than the nmap fingerprint with high confidence (e.g. fingerprint says HP storage, Recog
  says Linux), the device type follows the OS (server) and the vendor is not HP; VMs and containers matched by a
  virtualization integration never take type or vendor from the fingerprint (no role-specific service → server /
  windows), and the IP "Probe" page summary agrees with the periodic probe; an already misjudged "Storage · HP" becomes
  "Server" on the next probe without keeping HP as model (`test_ip_identify.py`). On production check a PVE LXC
- [ ] **MikroTik lease hostnames** use their own source, not "manual" (`tests/test_hostname_reports.py`): a typed hostname
  is not overridden, and the lease hostname disappears when the lease does

### Recent (v0.5.6x–0.5.7x)

- [ ] **BMC out-of-band console** (IPMI SOL, Beta): enable per IP (`bmc_enabled`, migration 0092) → connect
  button appears on IP detail + Connections; connects with cipher auto-fallback (17→3); credential vault
  “remember” persists (`protocol='bmc'`) and pre-fills next time; RBAC = same as SSH (per-object + can_ssh);
  session open/close audited; **Setup guide** modal opens (form/toolbar/blank-hint) with troubleshooting;
  **Fit to window** button sends `stty` (tooltip warns it sends a command).
- [ ] **Disconnected overlay** (SSH / RDP / VNC / noVNC / xterm / BMC): dropping the session shows a big
  centered “Disconnected” + broken-link icon **over the display only** (toolbar / Reconnect stay clickable);
  fades out on reconnect.
- [ ] **Connections OS column** matches the IP-detail page (shared `OsCell`): OS icon + localized family name
  + （source） annotation, raw guess on hover; value is the source-precedence-resolved OS.
- [ ] **Scan-agent OS detection** (agent ≥ 1.7.0): appliances/BMCs are no longer mis-guessed; Debian
  appliance (SSH banner) → `Debian`, Windows via SMB/Service-Info → `Windows`, device-model-only guesses
  (NAS / OpenWrt / router) are dropped to unknown rather than shown.
- [ ] **Notification i18n**: switch UI language (繁中 ⇄ English) → the bell **and** the Notifications page
  render in the current language (IP-request, anomaly, cert, stale-IP); old notifications fall back to stored text.
- [ ] **Notification channels** (Admin → 通知發送設定): Telegram / Slack / Teams / Nextcloud Talk / Zulip each
  save (encrypted token/webhook; a saved value shows as set and is kept when the field is left blank), the per-channel **Test** button delivers, and an
  enabled channel receives a matrix-fired event (e.g. an IP request) alongside Email/in-app.
- [ ] **Export button** on table pages is bordered (matches Columns / Refresh).
- [ ] **DHCP-server / gateway IP marking** (migration 0090 `is_dhcp_server`): OPNsense/pfSense DHCP-server IPs
  and gateways are flagged; IP detail shows the DHCP-server / gateway / in-DHCP-range badges.
- [ ] **LibreNMS auto-create device IPs** (migration 0091 default on): a LibreNMS-only device's primary IP is
  created in the matching (scoped) subnet; ambiguous overlaps are skipped, not mis-placed.
- [ ] **PVE browser console** (noVNC for VMs / xterm for CTs, migration 0089): per-IP toggle on PVE VM/CT IPs;
  connects with the PVE account; orange button + PVE badge on IP detail + Connections.
- [ ] **Status light in the IP detail header**: a light left of the address, the same colour as that IP in the IP list (online green,
  recent amber, offline red); hover lists when each source last saw it; the create IP form shows no light
- [ ] **Change log sources are translated**: no raw codes in the IP detail change log or the IP changes page's source filter and tags
  (`system`, `user` in Chinese and Japanese); a new source without all three translations fails
  `src/i18n/__tests__/changeSourceLabels.test.ts`
- [ ] **All probe fields shown** (agent 1.17.4, `tests/test_ip_identify_fields.py`, `e2e/ip-identify.spec.ts`): probing a Windows host
  shows a Windows name row (computer, domain or workgroup), port counts (open/closed/filtered), scan (duration, hops, estimated
  uptime) and a source after each name; a TLS host gets the certificates and host keys card (subject, issuer or self-signed, expiry
  with a 30-day warning, fingerprint with the full value on hover) and SSH keys are SHA256; services named only from the port are
  marked, cut script output is marked as truncated, and the reasons list explains an unused fingerprint and similar
- [ ] **Probe misreadings fixed**: a failed nmap run shows why instead of "no response"; probing an IPv6 address really runs; after a
  silent previous probe the comparison says ports cannot be compared instead of listing every port as new; a changed SSH host key or
  certificate is listed with a warning
- [ ] **Change impact preview** (migration 0187; `tests/test_change_impact_*.py`, `e2e/change-impact.spec.ts`): while off, the menu, IP
  and device pages show no entry and the API returns 403 `impact_feature_disabled`; turning it on in System settings shows them. "Preview
  renumber" on an IP page → create and analyse → the result page says nothing has been changed; findings show disposition, severity,
  category and a reason sentence, and expand to evidence with observed and collected times and the rule version; the gaps list shows
  unconfigured integrations, stale sources (one line per integration), CNAMEs not stored and so on; zero findings never reads as safe
- [ ] **Preview verdicts**: a new IP that is registered or reserved, reserved in DHCP for another NIC, or recently seen is a blocker; a CIDR
  rule covering both addresses is informational; an alias cycle is a gap and makes the result partial; shared aliases on decommission say
  to remove only the member; 192.0.2.1 does not match a note that says 192.0.2.10
- [ ] **Preview workflow and permissions**: after submitting, the creator cannot review their own plan; blockers cannot be approved;
  incomplete data allows only accept-risk with a reason; a new reference after approval makes "Start maintenance" fail with
  `impact_run_stale` and moves the plan back to draft; an account that sees only the subnet does not get DNS/firewall findings and is told
  the scope differs; another user's run or evidence id returns 404; Markdown/JSON exports follow the downloader's permissions
- [ ] **Preview AI**: with AI off the analysis still works and the AI buttons say it is unavailable; invented ids or addresses are rejected,
  repaired once and then replaced by a template summary; drafted tasks are saved only when ticked; read-only MCP keys do not see the
  plan-creating tools, and creating needs the draft token from `impact_prepare_scenario`
- [ ] **Unmanaged address rows and page** (`e2e/subnet-grid-unmanaged.spec.ts`): with auto-create off, let the scan agent see an
  unregistered address → the IP list has a row with a dashed orange marker, an Unmanaged tag, MAC and vendor and "seen by scan agent ·
  N minutes ago", not folded into a free range; clicking the grid cell or the row opens the address page with Probe (admins), Add and Back
  at the top right; after adding, it switches to the new record's IP page and the grid and list show it as a normal registered address

---

### Appendix: throwaway test DB commands (on the prod host, **never the prod DB**)

```bash
set -a; source /etc/jt-ipam/backend.env; set +a
sudo -u postgres psql -c "DROP DATABASE IF EXISTS jt_ipam_test;"
sudo -u postgres psql -c "CREATE DATABASE jt_ipam_test OWNER ${POSTGRES_USER} ENCODING UTF8 TEMPLATE template0;"
sudo -u postgres psql -d jt_ipam_test -c "CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS pg_trgm;"
cd /opt/jt-ipam/backend
POSTGRES_DB=jt_ipam_test .venv/bin/alembic upgrade head
JTIPAM_TEST_DATABASE_URL="postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/jt_ipam_test" .venv/bin/pytest -q
sudo -u postgres psql -c "DROP DATABASE IF EXISTS jt_ipam_test;"
```
