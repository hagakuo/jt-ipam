# jt-ipam Release Test Checklist

> zh-TW version: [TEST_CHECKLIST_zh-TW.md](TEST_CHECKLIST_zh-TW.md).

> Rule: **before bumping the `version` in `frontend/package.json`, run this whole
> checklist once; only release when everything is green.**
> Treat it as the manual gate. Fix the red ones first — do not ship sick.

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

## 2. Database / migration (use a throwaway test DB, never touch prod data)

- [ ] A fresh DB upgrades from 0001 to head cleanly: run `alembic upgrade head`
  against `jt_ipam_test`
- [ ] Each new migration has a `downgrade()` and survives one
  `alembic downgrade -1` then `upgrade head` round-trip
- [ ] No "model changed but migration forgotten": after upgrading to head the app
  starts without an asyncpg "column does not exist" error

## 3. Backend integration tests (test DB + pytest, thorough)

- [ ] With `JTIPAM_TEST_DATABASE_URL` set, `.venv/bin/pytest -q` is all green
  (e2e CRUD / auth / each module)
- [ ] Auth: login, refresh, TOTP, permissions (unauthorized `require_admin`
  endpoints return 401/403)
- [ ] Core CRUD: sections / subnets / addresses / devices / customers / locations / racks
- [ ] Audit chain: write operations are audited and chain integrity verifies

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

## 5b. Deploy-script flows (throwaway environment, **never run install on dev/prod**)

- [ ] **Fresh install**: on a clean LXC/VM run `scripts/install-debian.sh`; the
  service comes up and you can log in
- [ ] **Upgrade**: against a previous-version environment run
  `scripts/jt-ipam-upgrade.sh`; it upgrades cleanly and can roll back if needed
- [ ] If this release added a directory / package / service / DB extension / env,
  confirm **both scripts are in sync**
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

## 5c. Real-browser testing — **mandatory for every release that touches the UI**

Type checks, unit tests and API tests all pass while a page renders the wrong
thing, renders nothing, or puts it in the wrong place. Defects this project has
shipped that were only ever visible in a browser: a column added to a table but
not to the column-picker defaults (so it never appeared), an export that wrote
`undefined` into the report, a date overlapping its buttons, file names that
failed to line up by 16px, and a console that could not connect at all because
the reverse proxy dropped the WebSocket upgrade.

- [ ] `cd frontend && pnpm exec playwright test smoke` (no backend; self-starts
  vite preview) all green
- [ ] Against a deployed instance (`E2E_BASE_URL` + `E2E_ADMIN_PASS`) run the
  **whole** suite: `pnpm test:e2e`. Data-dependent specs need real data — run those
  against a deployed instance, not an empty test DB
- [ ] **Every changed page opened in an actual browser**, console watched: no errors,
  no blank regions, no `undefined` / raw JSON / untranslated i18n keys on screen
- [ ] **A new spec covering what this release changed.** Assert on the effect, not on
  the UI's own claim: read the file back off the remote host, reload the page after
  saving, compare the downloaded bytes. "已上傳" on screen is not evidence
- [ ] **Measure geometry, don't eyeball it** — `boundingBox()` whenever the point is
  alignment, overlap or spacing; a screenshot hides a 16px error
- [ ] New text checked in both locales (switch to English, confirm no key leaks)

## 5d. System export / import (cross-instance migration) — **run in full every release that touches it**

- [ ] **Unit (no DB)**: `pytest tests/test_system_transfer.py -q` — crypto seal/open
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

## 6. Manual page review (browser, after deploy)

- [ ] Login / logout / theme switch (light / dark / auto)
- [ ] Subnets: list, tree, IP list (incl. idle-range rows spanning columns), edit
- [ ] Devices / racks: sorting (natural IP order), consistent action-button height,
  floor-plan upload + drag-to-place + select
- [ ] Topology: nodes / links, VPN pairing links, legend
- [ ] Scan agents / sync jobs: pages render, no console errors

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

## 7b. VMware ESXi / vCenter integration (Admin → 整合 VMware) — **Beta**

> The SOAP endpoint is always `<url>/sdk`. One implementation covers **both** a standalone ESXi
> host and vCenter — they are the same VIM API, and ContainerView absorbs the depth difference.
> Use a **read-only** account: this integration never writes. Free/unlicensed ESXi exposes the
> API read-only anyway, which is exactly what is needed here.

- [ ] Add instance: URL + username/password, **Verify TLS off** for a self-signed cert; save
  (password write-only, never returned). Editing with an empty password leaves it unchanged.
- [ ] **Test connection** → step-by-step diagnostics: RetrieveServiceContent (product + version),
  Login, RetrievePropertiesEx (VM count). A wrong password must fail at **Login** with VMware's own
  message, not a bare "server error" — VMware returns auth failures as a SOAP Fault over HTTP 500.
- [ ] **Sync now** → VM count returns; clusters list shows the instance with type `vmware`;
  VMs carry name / power state / vCPU / memory / host.
- [ ] **Field reality check (first real hardware run)**: compare a few VMs against the vSphere client.
  Powered-off VMs have no `guest.*`, VMs without VMware Tools have no IP, templates have no
  `runtime.host` — none of these may break the sync; they should simply come back empty.
- [ ] **Paging**: on a vCenter with more than 200 VMs, the count matches the vSphere client
  (a dropped continuation token loses the rest **silently**).
- [ ] **IP matching**: an in-scope IP reported by VMware Tools links to the existing address;
  an address not in IPAM is **not** created. With overlapping subnets and no scope set, the
  ambiguous address is skipped rather than guessed.
- [ ] **Deleted VM**: remove a VM in vSphere → next sync removes it from the list.
- [ ] **PVE regression (shared tables)**: Proxmox clusters/VMs/interfaces are untouched by an ESXi
  sync, `legacy_vmid` and `kind=ct` still correct, and 進階 → 虛擬化 (Proxmox VE) still lists only PVE
  while 虛擬化 (VMware) lists only VMware. Device / IP links from PVE VMs still resolve.
- [ ] Delete instance; periodic `jt-ipam-sync` picks up enabled instances every ~5 min without errors.

## 8. Recent feature spot-checks

- [ ] **Notification matrix** (Admin → 通知發送設定): toggle events × (in-app / email); save persists; events fire
  per matrix (IP request, cert expiring/deployed/drift, anomaly).
- [ ] **Cert distribution `files` profile**: writes cert files only, no reload/restart.
- [ ] **Anomaly page**: tabs, per-table column picker, `ip_address_id` hidden by default, MAC drift shows IP/hostname.
- [ ] **MCP client-config generator** (LLM/AI): button outputs Claude Desktop / opencode / mcpo / generic snippets.
- [ ] **LLM provider = OpenAI-compatible** (Admin → LLM/AI): switching to it shows the data-egress warning
  and the API-key field; the model dropdown repopulates from `/v1/models` (empty dropdown = the wrong path
  is being called); a base URL already ending in `/v1` is not doubled; chat and semantic search both work.
  Switching back to Ollama restores the `/api/tags` list. `select value from system_settings where key='llm'`
  must show **no plaintext key** — only `api_key_enc`; the settings page never returns the key itself.
- [ ] **Embedding dimension** (Admin → LLM/AI): the **Check dimension** button reports the model's actual
  dimension against the column size. After changing the embedding model, a reindex must report
  `failed: 0` — and if it reports `0 indexed` the failure count and reason must be visible, never a bare
  zero. A candidate model must also produce **different vectors for different Traditional Chinese
  descriptions** (English-only models collapse them and look fine while ranking at random).
- [ ] **Add address in a subnet**: the create form has a required IP field (issue #14).
- [ ] **Attach IPs by NIC MAC** (Admin → 系統設定): off by default on an existing install; **Preview**
  reports a count plus per-reason skips and changes nothing; enabling it attaches on the next sync round
  and writes one IP-change-log row per address with the match reason. Clear a device link by hand, then
  confirm the next round does **not** restore it (the rule that keeps the job from fighting the operator).

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
- [ ] **Scan-agent OS detection** (agent ≥ 1.7.0): appliances/BMCs are no longer mis-guessed — Debian
  appliance (SSH banner) → `Debian`, Windows via SMB/Service-Info → `Windows`, device-model-only guesses
  (NAS / OpenWrt / router) are dropped to unknown rather than shown.
- [ ] **Notification i18n**: switch UI language (繁中 ⇄ English) → the bell **and** the Notifications page
  render in the current language (IP-request, anomaly, cert, stale-IP); old notifications fall back to stored text.
- [ ] **Notification channels** (Admin → 通知發送設定): Telegram / Slack / Teams / Nextcloud Talk / Zulip each
  save (encrypted token/webhook; “set — leave blank to keep”), the per-channel **Test** button delivers, and an
  enabled channel receives a matrix-fired event (e.g. an IP request) alongside Email/in-app.
- [ ] **Export button** on table pages is bordered (matches Columns / Refresh).
- [ ] **DHCP-server / gateway IP marking** (migration 0090 `is_dhcp_server`): OPNsense/pfSense DHCP-server IPs
  and gateways are flagged; IP detail shows the DHCP-server / gateway / in-DHCP-range badges.
- [ ] **LibreNMS auto-create device IPs** (migration 0091 default on): a LibreNMS-only device's primary IP is
  created in the matching (scoped) subnet; ambiguous overlaps are skipped, not mis-placed.
- [ ] **PVE browser console** (noVNC for VMs / xterm for CTs, migration 0089): per-IP toggle on PVE VM/CT IPs;
  connects with the PVE account; orange button + PVE badge on IP detail + Connections.

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
