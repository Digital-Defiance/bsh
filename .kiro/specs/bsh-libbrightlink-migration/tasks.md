# Implementation Tasks

This is the executable plan for the bsh ↔ libBrightLink migration. It is
organised so an agent (or human contributor) can pick up the spec in a
fresh workspace and execute the tasks in order. Each task is independently
buildable and testable, mirroring the commit ordering in
`requirements.md` Requirement 8.

The work splits across two repositories:

- **libBrightLink** (`https://github.com/Digital-Defiance/libbrightlink`):
  Tasks 1–4. Adds the v0.2 verb surface, tags `v0.2.0`, pushes upstream.
- **bsh** (`https://github.com/Digital-Defiance/bsh`): Tasks 5–10. Pulls
  in libBrightLink as a submodule, rewires the build, rewrites the module.

Tasks reference requirement IDs from `requirements.md`. When a task says
"satisfies Req 3.4", that's the acceptance criterion the task is
implementing.

---

## Phase A: libBrightLink v0.2 (upstream repo)

Workspace: clone `Digital-Defiance/libbrightlink` into a fresh location
and work on a `v0.2.0-prep` branch. Reference implementation lives at
`/Volumes/Code/bsh/Src/Modules/brightlink.c` (1,963 lines, contains
working code for every v0.2 verb).

### Task 1: Implement `bl_deliver` (LINK_DELIVER)

- [ ] **1.1** Add `bl_deliver` declaration to
  `include/brightlink/brightlink.h` per the design doc's "Header additions"
  section.
- [ ] **1.2** Add `src/brightlink_deliver.c` (new file). Lift the
  implementation from `bsh/Src/Modules/brightlink.c::link_emit_deliver`
  (the function exists in the reference). Adapt to handle-based API: the
  client carries the per-direction counter and `K_session`; the function
  builds the §4.6.3 length-prefixed AAD, AES-GCM-wraps the body, writes
  the request frame, reads/decrypts the reply.
- [ ] **1.3** Wire lazy `bl_register` per Requirement 1.7 — copy the
  pattern from `src/brightlink.c::bl_geo_get`'s opening lines.
- [ ] **1.4** Wire bridge-error capture per Requirement 1.8 — copy
  `capture_bridge_error()` invocations from existing geo code.
- [ ] **1.5** Add `tests/test_bl_deliver.c`: drive `mock-brightnexus`
  through one round trip, assert `BL_OK` and that the bridge received
  decryptable bytes that match the input.
- [ ] **1.6** Update `meson.build` to compile `src/brightlink_deliver.c`
  and register the new test.
- [ ] **1.7** Verify: `meson setup build && ninja -C build && meson test
  -C build` passes locally on macOS.

_Satisfies: Req 1.1, 1.7, 1.8._

### Task 2: Implement the four new geo verbs

- [ ] **2.1** Add struct typedefs for `bl_geo_status_t`, `bl_geo_proximity_t`,
  `bl_geo_zone_t` to `include/brightlink/brightlink.h` per the design doc.
- [ ] **2.2** Add function declarations for `bl_geo_status`,
  `bl_geo_proximity`, `bl_geo_zone`, `bl_geo_refresh`.
- [ ] **2.3** Implement each in `src/brightlink_geo_verbs.c` (new file).
  Each is ~30 lines: build the JSON request, send via the existing
  `bl_send_request` helper, parse the response into the typed struct.
  Lift JSON-parsing helpers (`json_field_str`, `json_field_double`, etc.)
  from `src/brightlink.c` if they're not already exposed for cross-file
  use; keep them `static` per file.
- [ ] **2.4** Argument validation per Requirement 1.3 (NULL/empty zone),
  1.5 (timeout 1..300): return `BL_ERR_INVALID_ARG` before any bridge
  contact.
- [ ] **2.5** Add `tests/test_geo_verbs.c`: one round-trip test per verb
  against `mock-brightnexus`. The mock needs to grow handlers for the new
  verbs — extend `tests/mock-brightnexus/mock-brightnexus.c` with the four
  new verb branches.
- [ ] **2.6** Verify the suite passes.

_Satisfies: Req 1.2, 1.3, 1.4, 1.5, 1.7, 1.8._

### Task 3: Implement `bl_push_subscribe` (LINK_PUSH)

- [ ] **3.1** Add `bl_push_event_t`, `bl_push_callback_t`,
  `bl_push_subscribe_config_t`, `bl_push_subscription_t` (opaque) to the
  header.
- [ ] **3.2** Add `bl_push_subscribe` and `bl_push_unsubscribe`
  declarations.
- [ ] **3.3** Implement in `src/brightlink_push.c` (new file). Spawns a
  background thread that owns a persistent socket; the callback runs on
  that thread per the design doc note. Use `pthread_create` /
  `pthread_join` directly — no new dependency.
- [ ] **3.4** `bl_push_unsubscribe` signals the thread to exit (close
  the socket, flag a stop bit), joins, frees the subscription struct.
- [ ] **3.5** Add `tests/test_push.c`: `mock-brightnexus` accepts a
  push subscribe, sends one canned event, then closes. Test asserts the
  callback fired with the expected `event_json`.
- [ ] **3.6** Document the threading model in the header (callback runs
  on a background thread, caller's responsibility to synchronise).

_Satisfies: Req 1.6._

### Task 4: Bump version, write changelog, tag, push

- [ ] **4.1** Bump `BL_VERSION_MINOR` to `2`, `BL_VERSION_PATCH` to `0`
  in `brightlink.h`. Update `bl_version()` body.
- [ ] **4.2** Add `CHANGELOG.md` entry listing every new public symbol
  by name (functions, structs, typedefs).
- [ ] **4.3** Run the full test suite (existing v0.1 tests + the v0.2
  tests added in Tasks 1–3) on macOS, Ubuntu noble, Ubuntu latest. If
  any v0.1 test regresses, that's a Req 1.10 violation — fix before
  proceeding.
- [ ] **4.4** Verify Req 1.10 by `nm`-ing the v0.1 release and the
  v0.2 build, diffing exported symbols. Every v0.1 symbol must still be
  present, with the same name.
- [ ] **4.5** Commit + push to `Digital-Defiance/libbrightlink:main`
  (or a `v0.2.x` release branch — implementer's call). Wait for CI to
  go green.
- [ ] **4.6** Tag `v0.2.0` annotated:
  `git tag -a v0.2.0 -m "v0.2.0: full BrightLink Protocol surface for bsh"`.
  Push the tag: `git push origin v0.2.0`.
- [ ] **4.7** Record the commit SHA the tag points at — bsh's submodule
  pin needs the exact 40-character SHA per Req 8.4.

_Satisfies: Req 1.9, 1.10, 8.1._

---

## Phase B: bsh module rewrite

Workspace: clone `Digital-Defiance/bsh` into a fresh location, branch
`brightlink-libbrightlink-migration` from `main`. Reference implementation
of the pre-migration module is the current
`Src/Modules/brightlink.c` on `main`.

### Task 5: Capture pre-migration test baselines

- [ ] **5.1** On the migration branch, ensure the build is clean and
  the test-harness passes against the **pre-migration** module.
- [ ] **5.2** Run each suite with vitest's JSON reporter, write outputs
  to `test-baselines/`:

  ```sh
  mkdir -p test-baselines
  cd test-harness
  yarn test:against-real-brightnexus --reporter=json \
    > ../test-baselines/against-real-brightnexus.json
  yarn test:against-real-bsh --reporter=json \
    > ../test-baselines/against-real-bsh.json
  yarn test:against-real-client --reporter=json \
    > ../test-baselines/against-real-client.json
  yarn test:unit --reporter=json \
    > ../test-baselines/unit.json
  ```

- [ ] **5.3** Commit: `test-harness: capture pre-migration baselines`.

_Satisfies: Req 7.6._

### Task 6: Add libBrightLink as a submodule

- [ ] **6.1** Add the submodule:

  ```sh
  git submodule add https://github.com/Digital-Defiance/libbrightlink.git \
      subprojects/libbrightlink
  cd subprojects/libbrightlink
  git checkout <SHA from Task 4.7>
  cd ../..
  git add .gitmodules subprojects/libbrightlink
  ```

- [ ] **6.2** Verify the gitlink SHA matches Task 4.7's SHA exactly.
- [ ] **6.3** Verify the build still passes against the
  pre-migration `Src/Modules/brightlink.c`. The submodule is on disk but
  no source file references it yet — the build should be unchanged.
- [ ] **6.4** Verify the test-harness still passes.
- [ ] **6.5** Commit: `bsh: add libBrightLink submodule at v0.2.0`.

_Satisfies: Req 2.1, 8.2a, 8.4._

### Task 7: Wire `--with-libbrightlink` into the build

- [ ] **7.1** Edit `configure.ac`: add the `AC_ARG_WITH([libbrightlink])`
  block, the system probe, the submodule fallback, and the
  `AC_SUBST` calls per the design doc's "configure.ac changes" section.
- [ ] **7.2** Remove the existing `AC_CHECK_LIB([crypto], ...)` and
  `AC_CHECK_LIB([secp256k1], ...)` invocations (currently around lines
  858-869 of `configure.ac`). They become transitive deps via
  libBrightLink.
- [ ] **7.3** Edit the `bsh/brightlink` module's Makefile fragment to
  honor `$(BRIGHTLINK_PATH)` per the design doc's "Makefile fragment"
  section. The submodule path runs `meson setup` + `ninja` at build
  time; the system path uses `$BRIGHTLINK_CFLAGS` / `$BRIGHTLINK_LIBS`
  from `PKG_CHECK_MODULES`.
- [ ] **7.4** Regenerate `configure` (`autoreconf -fiv` or `./configure`
  with autotools).
- [ ] **7.5** Test all three modes:

  ```sh
  # Submodule path (default)
  ./configure --with-libbrightlink=submodule && make
  # System path (skip if no system libBrightLink installed)
  ./configure --with-libbrightlink=system && make
  # Auto path
  ./configure && make
  ```

- [ ] **7.6** Verify: the link line for `Src/Modules/brightlink.so` no
  longer mentions `-lcrypto` or `-lsecp256k1` directly. They appear as
  transitive deps from libBrightLink. `ldd Src/Modules/brightlink.so`
  on Linux still shows `libcrypto.so` and `libsecp256k1.so`, just from
  libBrightLink's `.pc` `Libs.private`.
- [ ] **7.7** Verify: `Src/Modules/brightlink.c` is **unchanged** —
  this commit is build-system only. The pre-migration in-module
  protocol code still runs at runtime.
- [ ] **7.8** Run the test-harness; everything should still pass
  (Req 8.3).
- [ ] **7.9** Commit: `bsh: configure --with-libbrightlink wiring`.

_Satisfies: Req 2.2–2.10, 8.2b, 8.3._

### Task 8: Rewrite `Src/Modules/brightlink.c` as a glue layer

This is the big commit. It touches *only* `Src/Modules/brightlink.c`
and its build-generated companions (Req 8.5).

- [ ] **8.1** Save a copy of the pre-migration file for reference:

  ```sh
  cp Src/Modules/brightlink.c /tmp/brightlink-pre-migration.c
  ```

- [ ] **8.2** Rewrite `Src/Modules/brightlink.c` per the design doc's
  "bsh Module Rewrite" section. Walk through each of the file-level
  pieces:
  - [ ] Module entry points (`setup_`, `features_`, `enables_`,
    `boot_`, `cleanup_`, `finish_`).
  - [ ] `bintab[]` with the two `BUILTIN(...)` rows.
  - [ ] `module_features` aggregator.
  - [ ] `static bl_client_t *bsh_link_client_g = NULL;` and
    `bsh_link_client(void)` helper.
  - [ ] `bin_bsh_inject` handler: argv parse, stdin read, `bl_deliver`
    call, error mapping, exit code.
  - [ ] `bin_link_geo` handler: `--json` strip, subcommand dispatch,
    one `bl_geo_*` call per branch, printer dispatch.
  - [ ] Five `link_geo_print_*` printers (status, zone, proximity,
    refresh, get) with both plain-mode and JSON-mode branches.
  - [ ] Error-string preservation table at the top of the file as a
    block comment listing every preserved string and its origin.
- [ ] **8.3** Ensure no forbidden symbols/includes per Req 4.1–4.5:
  - [ ] Grep for `link_aes_`, `link_gcm_`, `link_hkdf_`, `link_ecies_`,
    `link_secp_`, `link_b64`, `link_build_transcript`,
    `link_build_deliver_aad`, `link_verify_p256_`, `link_register_`,
    `link_emit_`, `link_pinned_`, `link_pin_`, `link_socket_`,
    `link_resolve_socket`, `link_send_request`, `link_write_all`,
    `link_read_until_brace`, `link_json_` — all must be **zero hits**.
  - [ ] Grep for `<openssl/`, `<secp256k1` — all must be zero hits.
  - [ ] Grep for direct `socket(`, `connect(`, `bind(`, `send(`,
    `recv(`, `read(.*fd`, `write(.*fd` — all must be zero hits.
- [ ] **8.4** Build: `make`. Resolve any compile errors.
- [ ] **8.5** Smoke test: load the module in a built `bsh`,
  invoke `bsh-inject --type X --context Y` with a small body on
  stdin, then `link-geo status`. Both should produce sensible output.
- [ ] **8.6** Run the test-harness against the post-migration module:

  ```sh
  cd test-harness
  yarn test:against-real-brightnexus --reporter=json \
    > /tmp/post-against-real-brightnexus.json
  yarn test:against-real-bsh --reporter=json \
    > /tmp/post-against-real-bsh.json
  yarn test:against-real-client --reporter=json \
    > /tmp/post-against-real-client.json
  yarn test:unit --reporter=json \
    > /tmp/post-unit.json
  ```

- [ ] **8.7** Diff each pair against the baselines from Task 5.2.
  Every test that was `passed` pre-migration must still be `passed`.
  No test transitions to `failed`, `skipped`, or `todo` (Req 7.7).
  If any test regresses, fix the rewrite before continuing.
- [ ] **8.8** Measure module size:

  ```sh
  cloc --quiet --csv --include-lang=C Src/Modules/brightlink.c
  ```

  Target ≤600 lines (informational only per Req 4.8). If higher, write
  the rationale into the commit message.
- [ ] **8.9** Commit: `bsh: rewrite Src/Modules/brightlink.c against libBrightLink`.

  Commit body should include:
  - The cloc result.
  - If >600 lines, the architectural reason for the overage.
  - A reference to this spec.
  - The pre-migration baseline → post-migration result diff summary.

_Satisfies: Req 3 (all), Req 4 (all), Req 5 (all), Req 6 (all),
Req 7 (most), Req 8.2c, 8.5._

### Task 9: Optional cleanup

- [ ] **9.1** If the rewrite leaves any pre-migration helpers,
  comments, or `configure.ac` fragments unused, remove them in a
  follow-up commit.
- [ ] **9.2** Verify build + test-harness still pass.
- [ ] **9.3** Commit (if anything to commit): `bsh: post-migration cleanup`.

_Satisfies: Req 8.2d._

### Task 10: Open the bsh PR

- [ ] **10.1** Push the migration branch to GitHub.
- [ ] **10.2** Open a pull request titled "bsh: migrate brightlink module
  to libBrightLink v0.2".
- [ ] **10.3** PR description must include (Req 8.7):
  - The one-command revert path:
    `git revert <SHA-of-rewrite-commit>` returns
    `Src/Modules/brightlink.c` to its pre-migration content while
    leaving the submodule and build-system commits in place. The
    revert continues to build cleanly because the submodule-add and
    build-system commits are independent of the rewrite.
  - The cloc result for the rewritten module.
  - The baseline → post-migration test-harness pass count.
  - A link to the libBrightLink v0.2.0 tag and the SHA the submodule
    is pinned to.
- [ ] **10.4** Verify CI on the PR is green for both
  `against-real-brightnexus` and `against-real-bsh`.
- [ ] **10.5** Hand off to maintainer review.

_Satisfies: Req 8.6, 8.7._

---

## Definition of Done

The migration is complete when all of the following are true:

- [ ] libBrightLink `v0.2.0` is tagged on `Digital-Defiance/libbrightlink`
  and CI is green on the tag.
- [ ] All four bsh test-harness suites pass on the migration branch with
  zero regressions vs. the pre-migration baselines.
- [ ] `Src/Modules/brightlink.c` contains no symbol from the
  forbidden-prefix list in Req 4.2/4.3/4.4 and no `<openssl/...>` or
  `<secp256k1*.h>` include.
- [ ] `nm` of the libBrightLink v0.1 release and v0.2 release shows every
  v0.1 public symbol still present (no Req 1.10 violations).
- [ ] The bsh PR description documents the revert path and links the
  submodule pin to the v0.2.0 tag.
- [ ] A `git revert <rewrite-commit-SHA>` followed by `make` and
  `yarn test` succeeds, demonstrating the revert is clean.

## Estimated Effort

| Phase | Tasks | Rough effort | Risk |
|-------|-------|--------------|------|
| A. libBrightLink v0.2 | 1–4 | 1–2 days of focused work | Low — reference implementation exists in bsh module |
| B. bsh rewrite | 5–10 | 1 day, mostly mechanical | Medium — error-string preservation requires care |

Total: ~3 days of focused work, single contributor, assuming no bridge
behaviour changes are uncovered during testing. Bridge surprises (the
real BrightNexus emitting subtly different bytes than the mock) would
extend Phase B; everything else is well-bounded.
