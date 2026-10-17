# Keystone core (plan 1) — rulings and deferred follow-ups

Generated from the SDD ledger at completion of plan 1 (branch feat/core). Rulings = decisions taken during execution; 'minor (deferred)' = known follow-ups.

Ruling: product renamed to Keystone across plan/spec/code before execution — user chose rename-first — cost if wrong: one mechanical revert commit
Ruling: Docker volume `authi-data` keeps legacy name — renaming would orphan generated Postgres password vs existing postgres-data volume — cost if wrong: cosmetic inconsistency
Ruling: pre-flight scan delegated to one subagent — plan is 220KB; keeping it out of controller context — cost if wrong: a missed conflict surfaces in task review instead
Ruling: Task 1 already satisfied by existing scaffold+config (superset, 9 tests pass); do not overwrite src/config.ts — plan version makes KEYSTONE_SECRET_KEY/DATABASE_URL mandatory and breaks zero-config deploy — cost if wrong: later tasks must adapt to Config shape (it matches plan interface)
Ruling: Task 8 OidcClientMetadata = type alias with literal fields (not interface) so Task 12 typechecks against oidc-provider AdapterPayload; apply L5167 jwks cast up front — cost if wrong: small type rework
Ruling: Task 10 test at plan L3764 asserts not.toHaveProperty('clientSecret') and body not containing 'client_secret_enc' instead of no 'client_secret' substring — tokenEndpointAuthMethod legitimately contains it — cost if wrong: weaker assertion
Ruling: Task 14 merges into existing Docker setup (keep keystone-init, authi-data + postgres-data volumes, loopback port, private network, scripts/); add migrations+views COPY, bootstrap env passthrough, commented Traefik labels — avoids orphaning DB / exposing port — cost if wrong: diverges from plan's compose file
Ruling: Task 14 smoke test runs under `docker compose -p keystone-smoke` with no .env, never `down -v` on the real project — plan version would wipe user DB + keys — cost if wrong: none
Ruling: keep 503 JSON /healthz behaviour, implemented in Task 9 app.ts; README merged (keep zero-config + mock sections) — cost if wrong: minor
Ruling: Task 13 header(): split on comma only for Host/Proto, not X-Forwarded-Uri — URIs may contain commas — cost if wrong: none
Ruling: plan L11 spec path fixed to existing filename (no file renames) — cost if wrong: none
Ruling: replace vacuous encryption test (plan L4278) and weak hash assertions with real ones — cost if wrong: none
Ruling: logout without CSRF accepted for plan 1 (spec deviation, deferred to plan 4 cookie+CSRF work) — cost if wrong: logout-CSRF nuisance until plan 4
Ruling: advisory lock around SigningKeyService.ensureKeys (Task 11) — concurrent starts must not create duplicate keys (Review Focus 5) — cost if wrong: none
Ruling: validate usernames against regex in bootstrap and CLI (Task 14) — cost if wrong: none
Ruling: skip_consent / client_credentials deferred to plan 4 as plan states — cost if wrong: none
Ruling: weak hash assertions (plan L2035, L3626) become toBe(hashToken(token)) — cost if wrong: none
Ruling: Task 6 test L2124 uses distinct IPs per id as intended (A4) — cost if wrong: none
Ruling: Task 13 test "omits the email header" renamed to match empty-header behaviour (A19) — cost if wrong: none
Ruling: provider.proxy=true kept with comment (D4) — needed behind TLS proxy — cost if wrong: ctx.ip spoofable for logs only
Ruling: cookie Secure only when issuer https (Global Constraint over spec S-L141) — local http login must work — cost if wrong: cookie sent over http on misconfigured https-less deploy
Ruling: HKDF info strings `keystone:<purpose>` and dummy-password string frozen from now on — cost if wrong: none pre-deploy
Ruling: policy-check dup / groupNames dup (B4, A3, A17) optional; not blocking — cost if wrong: minor duplication
Task 2: minor (deferred): secrets.ts:76 createDecipheriv lacks authTagLength:16 → truncated GCM tags accepted (SECURITY hardening — final review should triage as must-fix)
Task 2: minor (deferred): tamper test covers ciphertext only, not tag/IV/truncated tag
Task 2: minor (deferred): deriveKey/createSecretBox don't check master key length (config validates 32 bytes — confirm)
Task 2: minor (deferred): passwords.ts:33 rejected dummyHash promise cached forever
Ruling: docker-compose.test.yml gets top-level name: keystone-test — shared project 'authi' with real deployment risks down/orphan cleanup hitting live containers — cost if wrong: none
Task 3: minor (deferred): migrate.ts:222 unlock failure in finally masks original migration error
Task 3: minor (deferred): no CHECK constraints for username/slug regex (app-level validation must cover)
Task 3: minor (deferred): allowed_group_ids uuid[] has no FK — group delete must clean up (Task 5 GroupService)
Task 3: minor (deferred): no test that failing migration rolls back unrecorded
Task 4: minor (deferred): audit.ts:69 non-numeric `before`/unbounded limit → 22P02 500; Task 10 audit route must validate (carry to Task 10)
Task 4: minor (deferred): EventBus default onError silent — composition root (Task 9 services.ts) must wire logger (carry to Task 9)
Task 4: minor (deferred): AppError lacks RFC7807 extensions field
Ruling: username regex + password min 12 enforced at entry layers (Task 10 zod schemas; Task 14 bootstrap + CLI create-admin/set-password) not in UserService — matches plan layering — cost if wrong: a future entry path bypasses validation
Task 5: minor (deferred): findByLogin OR username/email — username equal to another user's email makes login ambiguous (SECURITY-ish; final review triage)
Task 5: minor (deferred): user/group delete cascades emit no group.members_changed
Task 5: minor (deferred): GroupService.delete reads outside tx → duplicate group.deleted under concurrency; update before-read race on user.deactivated
Task 5: minor (deferred): create treats password '' as no password
Task 5: minor (deferred): missing tests (cascade, paging, empty patch, malformed ids)
Ruling: Task 6 rate limiter must be atomic under concurrency (plan-mandated code was check-then-write; reviewer Important) — reserve attempt rows before verifying, count including own; on success delete own reserved rows + clear user bucket — spec brute-force protection binding — cost if wrong: small extra writes per login
Task 6: carry to Task 9: login route must show same message for 'inactive' as invalid_credentials (no correct-password oracle)
Task 6: minor (deferred): blocked requests also reserve rows → rolling lockout; attacker can keep victim locked (account-lockout DoS; final review triage)
Task 6: minor (deferred): per-user bucket keyed by typed identifier — username vs email gives 2x budget; success clear only that form
Task 6: minor (deferred): audit stores raw identifier (password-in-username leak risk)
Task 6: minor (deferred): returning id order assumption; success clear drops other in-flight reservations
Task 6: minor (deferred): purge()/purgeExpired() need scheduling (Task 14 maintenance — verify)
Ruling: Task 7 keeps implementer's extra leading /%(control|2f|5c) rejection beyond brief regex — Review Focus 1 requires /%09/evil.com fallback; stricter is safe — cost if wrong: a legit path starting with encoded control/slash falls back to /
Ruling: Task 7 safeRedirectTarget returns canonical url.href for absolute targets, requires ^https?:// prefix and rejects control chars/whitespace in absolute targets; empty/'.' cookie domain guarded (minor 2 promoted: same function, bypass under misconfig) — plan shape returned raw string — cost if wrong: none
Task 7: minor (deferred): issuerUrl re-parsed per call; malformed issuerUrl throws (config validates?); ports unrestricted; relative targets with spaces/non-ASCII accepted raw
Task 8: carry to Task 10: API must validate slug regex and redirect URIs (httpUrl, exact strings, no control chars) on app create+update
Task 8: minor (deferred): update read-merge-write without lock; group existence check-then-write; test gaps (update conflict, nulling, getByClientId/list, non-UUID)
Task 9: carry to Task 10: validate launchUrl scheme http(s) on app create/update (home.eta href)
Task 9: carry to Task 14: pass app.log as createServices logger
Task 9: minor (deferred): logout test doesn't check cleared cookie domain; GET /logout untested; no XSS-echo test
Task 9: minor (deferred): double-submit CSRF cookie forgeable from sibling subdomain under cookie domain (login CSRF only) — consider HMAC-bound token (final review triage)
Task 9: minor (deferred): re-login doesn't destroy old session; logout validate() writes last_seen and skips audit for inactive
Task 10: minor (deferred): unauth requests to unknown /api/v1 paths get 404 not 401 (route enumeration) — add api.setNotFoundHandler
Task 10: minor (deferred): api token expiresAt accepts past dates; offset datetimes rejected
Task 10: minor (deferred): createdBy branch dead in plan 1; last_used_at write per request; deactivate + destroy sessions not transactional (validate checks is_active, so safe)
Ruling: createSecretBox(master, purpose) with separate boxes 'client-secrets' and 'signing-keys' (plan-mandated fixed 'secret-box' purpose from Task 2 violates spec per-purpose constraint) — fix before any prod data — cost if wrong: none (no deployed ciphertexts)
Ruling: Task 2 deferred minor GCM authTagLength:16 promoted into Task 11 fix round (same file, security) — cost if wrong: none
Task 11: minor (deferred): no partial unique index signing_keys(alg) WHERE status='active' (DB backstop)
Task 11: minor (deferred): Client upsert vs loadClient divergence if dynamic reg ever on; findByUid stale-row ordering; no rotate-vs-ensureKeys race test
Task 11: carry to Task 12/14: ensureKeys at startup + schedule purgeExpiredOidcPayloads
Ruling: Task 12 minors 2 (responseTypes ['code'] so discovery matches) and 3 (accurate proxy comment) promoted into fix round 1 — one-liners, security accuracy — cost if wrong: none
Task 12: minor (deferred): /oidc responses lack security headers (B3); logout inline script needs nonce if fixed
Task 12: minor (deferred): error after reply.hijack() leaves request hanging; provider server_error not logged to Fastify logger
Ruling: Task 13 minors 1-3 promoted (security): reject multi-valued X-Forwarded-Host with 400 (appending proxy → cross-app policy bypass; reverses my earlier leftmost-split for Host, Proto split kept); non-printable-ASCII username fails closed (500 + log) not ''; Cache-Control: no-store on all /outpost/auth responses — cost if wrong: a proxy that legitimately appends Host lists gets 400 (documented: proxy must overwrite)
Task 13: minor (deferred): one audit row per denied subrequest (noise); test gaps (forwardAuthEnabled false, hostile Uri, nginx forbidden); import order
Task 14: minor (deferred): README lacks "proxy must overwrite X-Forwarded-Host/-Proto" for Keystone's own host (provider.proxy=true reflects client host in discovery)
Task 14: minor (deferred): bootstrap validation before count check → crash-loop on established install with bad env password
Task 14: minor (deferred): bootstrap tx only holds lock (count/create/audit on pool, not atomic)
Task 14: minor (deferred): pre-listen startup failures bypass pino
Task 14: minor (deferred): Traefik label trustForwardHeader=true (plan) — false is safer
Task 14: minor (deferred): maintenance test thin (rate-limit purge, startMaintenance)
Ruling: final fix wave = Traefik trustForwardHeader=false; revoke OIDC artifacts (oidc_payloads by accountId) on deactivate/delete/password set/revoke sessions + CLI reset-password; hijack try/catch in interaction route; README proxy-overwrite note for Keystone host + KEYSTONE_HOST_PORT/issuer note; KEYSTONE_TRUST_PROXY true/false parsed as booleans; CLI reset-password clears user's login attempts — reviewer must-fix + cheap recommended — cost if wrong: small
Ruling: everything else in final triage deferred (see reviewer table); T5 findByLogin ambiguity must be fixed before plan 2 (upstream-synced emails)
Final: fix wave 225a77f..d707e2d re-review clean (4 minors: CRLF→LF churn in README/compose/.env.example; OIDC revoke tested on 2 of 5 paths; no index on payload->>accountId; user delete + revoke not transactional)
