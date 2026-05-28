# Design Document

## Overview

This document specifies the technical design for migrating the bsh module
`Src/Modules/brightlink.c` (1,963 lines, full inline BrightLink Protocol
implementation) to consume libBrightLink as a thin glue layer. It satisfies
Requirements 1–8 in `requirements.md`.

The migration is structurally invisible to bsh users: the `bsh-inject` and
`link-geo` builtin signatures, exit codes, stdout layouts, and stderr error
strings remain bit-for-bit identical to the pre-migration module. The win is
that bsh-iputils and bsh share one canonical protocol implementation, so any
future BrightLink Protocol bug fix is a single library commit that flows to
both consumers via submodule pointer bumps.

The work is sequenced in two halves:

1. **libBrightLink v0.2** — extend the published library with the verb surface
   bsh requires (`LINK_DELIVER`, four geo verbs beyond `GET`, and `LINK_PUSH`
   subscribe). Tagged and pushed to upstream before any bsh commit references
   it.
2. **bsh module rewrite** — replace `Src/Modules/brightlink.c` with a glue
   layer that calls only the libBrightLink v0.2 public API. Lands on
   `bsh/main` as a sequence of independently-buildable, independently-revertable
   commits.

This document maps each requirement to a concrete design decision. Where a
design choice has alternatives, the chosen option is named and the discarded
alternatives are documented with the reason.

## Architecture

### Component Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│ bsh process (single-threaded zsh runtime)                          │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ bsh module: Src/Modules/brightlink.c (~500 lines, glue only) │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │ Module entry points (zsh ABI)                          │  │  │
│  │  │   setup_   features_   enables_                        │  │  │
│  │  │   boot_    cleanup_    finish_                         │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │ Builtin handlers                                       │  │  │
│  │  │   bin_bsh_inject ──► bl_deliver()                      │  │  │
│  │  │   bin_link_geo   ──► bl_geo_status / proximity / zone /│  │  │
│  │  │                       get / refresh                    │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │ Per-subcommand stdout printers                         │  │  │
│  │  │   link_geo_print_status / zone / proximity /           │  │  │
│  │  │   refresh / get                                        │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │ Module-global state                                    │  │  │
│  │  │   static bl_client_t *bsh_link_client_g = NULL;        │  │  │
│  │  │   static bl_client_t *bsh_link_client(void);           │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                     │
│                              │ public API only                     │
│                              ▼                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ libBrightLink v0.2 (static archive linked into module .so)   │  │
│  │   bl_client_new / _free / bl_register / bl_geo_*             │  │
│  │   bl_deliver / bl_push_subscribe / bl_pin_store_memory       │  │
│  │   (DD-ECIES, AES-GCM, HKDF, P-256, secp256k1 internally)     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                     │
│                              │ AF_UNIX SOCK_STREAM                 │
│                              ▼                                     │
└────────────────────────────────────────────────────────────────────┘
                ┌─────────────────────────────────┐
                │ BrightNexus bridge (out of      │
                │ scope; specified by RFC §3)     │
                └─────────────────────────────────┘
```

### Repository Layout (post-migration)

```
bsh/
├── .gitmodules                              # NEW: submodule entry
├── configure.ac                             # MODIFIED: --with-libbrightlink, drop -lcrypto/-lsecp256k1
├── subprojects/
│   └── libbrightlink/                       # NEW: submodule, pinned to v0.2.0
└── Src/
    └── Modules/
        ├── brightlink.c                     # REWRITTEN: ~500 lines glue
        ├── brightlink.mdd                   # UNCHANGED
        ├── brightlink.epro                  # REGENERATED
        ├── brightlink.mdh / .mdhi / .mdhs   # REGENERATED
        ├── brightlink.pro                   # REGENERATED
        └── brightlink.syms                  # REGENERATED
```

## libBrightLink v0.2 Surface (Requirement 1)

This section is a complete specification of the additions to libBrightLink's
public header. It exists in this design doc rather than in the libBrightLink
repo's own spec because the bsh migration is the consumer that drives the API
shape.

### Header additions to `include/brightlink/brightlink.h`

```c
/* ────── §4.6 LINK_DELIVER ────── */

bl_status_t bl_deliver(bl_client_t   *c,
                       const char    *type,
                       const void    *context, size_t context_len,
                       const void    *body,    size_t body_len);

/* ────── §9 LINK_GEO_STATUS ────── */

typedef struct {
    int    alive;             /* 1 if engine has ever produced a fix */
    char   engine_kind[32];   /* "CoreLocation" / "GeoClue" / "Mock" / ... */
    double last_fix_bd;       /* BrightDate of last fix, or 0 if none */
    double fix_age_seconds;   /* seconds since last fix, or -1 if none */
    double accuracy_m;        /* metres, or NAN if unknown */
} bl_geo_status_t;

bl_status_t bl_geo_status(bl_client_t *c, bl_geo_status_t *out);

/* ────── §9 LINK_GEO_PROXIMITY ────── */

typedef struct {
    int    in_zone;           /* 1 if currently inside the named zone */
    double brightdate;        /* BrightDate at which the result was evaluated */
} bl_geo_proximity_t;

bl_status_t bl_geo_proximity(bl_client_t        *c,
                             const char         *zone_id,
                             bl_geo_proximity_t *out);

/* ────── §9 LINK_GEO_ZONE ────── */

typedef struct {
    char   zone_id[128];      /* zero-length string if not in any named zone */
    double dwell_seconds;     /* seconds since entering the current zone */
    double brightdate;        /* BrightDate at which the result was evaluated */
} bl_geo_zone_t;

bl_status_t bl_geo_zone(bl_client_t *c, bl_geo_zone_t *out);

/* ────── §9 LINK_GEO_REFRESH ────── */

/* timeout_seconds is clamped 1..300; out-of-range returns BL_ERR_INVALID_ARG
 * without contacting the bridge. On success, *out is the post-refresh
 * position (same shape as bl_geo_get's output struct). */
bl_status_t bl_geo_refresh(bl_client_t       *c,
                           int                timeout_seconds,
                           bl_geo_position_t *out);

/* ────── §10 LINK_PUSH subscribe ────── */

typedef struct bl_push_subscription_s bl_push_subscription_t;

typedef struct {
    /* Wire-level event payload from the bridge, NUL-terminated JSON.
     * Lifetime: valid only for the duration of the callback; copy if needed
     * past return. */
    const char *event_json;
    size_t      event_json_len;
} bl_push_event_t;

typedef void (*bl_push_callback_t)(const bl_push_event_t *event,
                                   void                  *user_data);

typedef struct {
    const char         *topic;       /* §10 topic identifier, e.g. "geo:zone-transitions" */
    bl_push_callback_t  callback;    /* invoked from libBrightLink's reader thread */
    void               *user_data;   /* opaque pointer passed to callback */
} bl_push_subscribe_config_t;

bl_status_t bl_push_subscribe(bl_client_t                       *c,
                              const bl_push_subscribe_config_t  *cfg,
                              bl_push_subscription_t           **out);

void bl_push_unsubscribe(bl_push_subscription_t *sub);

/* ────── version bump ────── */

#define BL_VERSION_MAJOR 0
#define BL_VERSION_MINOR 2
#define BL_VERSION_PATCH 0
/* bl_version() returns "0.2.0" */
```

### Implementation notes

- **Source of truth for the v0.2 implementation**: the existing
  `bsh/Src/Modules/brightlink.c` already has working implementations of every
  v0.2 verb. The libBrightLink work is largely a port: extract the relevant
  per-verb function from `Src/Modules/brightlink.c`, adapt it to the
  handle-based `bl_client_t` API, and add it to libBrightLink's `src/`. The
  primitives (DD-ECIES, AES-GCM, HKDF, P-256, secp256k1) are already in
  libBrightLink's `brightlink_crypto.c`.
- **Lazy registration** (Requirement 1.7): every v0.2 verb wraps its first
  bridge round-trip with a `bl_register()` call when `c->session_active == 0`.
  This is the same pattern v0.1 `bl_geo_get` already uses.
- **Bridge-error capture** (Requirement 1.8): on `{"error": "..."}` envelope,
  v0.2 verbs follow v0.1's existing `capture_bridge_error()` pattern: extract
  the English string, store it on the client for `bl_last_bridge_error()`,
  zero `*out`, return `BL_ERR_BRIDGE_REFUSED`.
- **`bl_status_t` extensions**: no new values are required — the v0.2 verbs
  reuse `BL_OK`, `BL_ERR_TRANSPORT`, `BL_ERR_PROTOCOL`, `BL_ERR_CRYPTO`,
  `BL_ERR_BRIDGE_REFUSED`, `BL_ERR_INVALID_ARG`, `BL_ERR_OOM`. This satisfies
  Requirement 1.10's "no renumbering" constraint trivially.
- **`LINK_PUSH` reader thread**: `bl_push_subscribe` spawns a single
  background thread that owns a persistent socket to the bridge. The callback
  runs on that thread, not on the caller's thread. bsh consumers that don't
  need push (i.e., the current `bsh-inject` and `link-geo` builtins) won't
  call `bl_push_subscribe`, so the thread is paid for only when subscribed.
  This is documented in the header.

### Conformance test additions to libBrightLink

`tests/test_v02_verbs.c` (new): for each verb, hits the existing
`mock-brightnexus` binary with a known fixture and asserts the parsed
result matches. `tests/test_handshake_roundtrip.c` (existing): unchanged.

## bsh Module Rewrite (Requirements 3, 4, 5, 6)

### File-level structure of the new `Src/Modules/brightlink.c`

```c
/*
 * brightlink.c — bsh module: bsh-inject and link-geo builtins.
 *
 * This file is a thin glue layer over libBrightLink. The protocol code
 * (DD-ECIES, AES-GCM, HKDF, P-256, secp256k1, JSON parsing, socket I/O)
 * lives in libBrightLink (subprojects/libbrightlink/). This file contains
 * only zsh module plumbing, builtin argument parsing, and per-subcommand
 * stdout printing.
 */

#include "brightlink.mdh"
#include "brightlink.pro"
#include <brightlink/brightlink.h>     /* the only libBrightLink include */

/* No <openssl/...>, no <secp256k1*.h>, no JSON parser. (Requirement 4.2, 4.4) */

/* ─── module-global client (Requirement 5) ─── */

/* Single-threaded zsh execution model — no locking around access. */
static bl_client_t *bsh_link_client_g = NULL;

static bl_client_t *bsh_link_client(void)
{
    if (bsh_link_client_g) return bsh_link_client_g;

    bl_client_config_t cfg = {
        .agent_name    = "bsh",
        .agent_version = ZSH_VERSION,
        .socket_path   = NULL,                    /* libBrightLink resolves */
        .ttl_seconds   = 0,                       /* library default */
        .pin_store     = bl_pin_store_memory(),   /* Requirement 6.1 */
        .debug_stream  = (getenv("BRIGHTLINK_DEBUG") &&
                          getenv("BRIGHTLINK_DEBUG")[0])
                         ? stderr : NULL,
    };
    bsh_link_client_g = bl_client_new(&cfg);
    return bsh_link_client_g;
}

/* ─── builtin handlers (declared in bintab below) ─── */
static int bin_bsh_inject(char *nam, char **argv, Options ops, int func);
static int bin_link_geo  (char *nam, char **argv, Options ops, int func);

/* ─── per-subcommand stdout printers ─── */
static void link_geo_print_status   (const bl_geo_status_t   *s, int json);
static void link_geo_print_zone     (const bl_geo_zone_t     *z, int json);
static void link_geo_print_proximity(const bl_geo_proximity_t*p, int json);
static void link_geo_print_refresh  (const bl_geo_position_t *r, int json);
static void link_geo_print_get      (const bl_geo_position_t *g, int json);

/* ─── bintab and module entry points (Requirement 4.6) ─── */
static struct builtin bintab[] = {
    BUILTIN("bsh-inject", 0, bin_bsh_inject, 0, -1, 0, NULL, NULL),
    BUILTIN("link-geo",   0, bin_link_geo,   0, -1, 0, NULL, NULL),
};
static struct features module_features = { /* ... standard zsh shape ... */ };

int setup_   (Module m) { return 0; }
int features_(Module m, char ***features) { /* ... */ }
int enables_ (Module m, int **enables)    { /* ... */ }
int boot_    (Module m) { return 0; }
int cleanup_ (Module m) { return 0; }       /* Requirement 5.9: untouched */
int finish_  (Module m) {
    if (bsh_link_client_g) {                /* Requirement 5.6 */
        bl_client_free(bsh_link_client_g);
        bsh_link_client_g = NULL;
    }
    return 0;                               /* Requirement 5.7 */
}
```

### Call flow: `bsh-inject`

1. **Parse argv** for `--type T` and `--context C`. Reject unknown tokens
   with `unknown argument: <arg>` (Requirement 3.11). Require both flags
   with `--type and --context are required`.
2. **Read stdin** into a heap buffer up to `LINK_BUF_MAX` bytes
   (preserved from pre-migration; literal numeric value matters per
   Requirement 3.11). Overflow or `read(2)` error → exit 1 with
   `stdin read failed or exceeded N bytes`.
3. **Get the client**: `c = bsh_link_client();` if NULL, exit 1 with a
   stderr message (Requirement 5.5).
4. **Deliver**: `st = bl_deliver(c, T, C, strlen(C), body, body_len);`
5. **Map `bl_status_t` to bsh exit/stderr** per Requirement 3.10/3.11:
   - `BL_OK` → exit 0
   - any error → `fprintf(stderr, "%s: %s\n", nam, msg)` + exit 1
   - register-time error (lazy register inside `bl_deliver`) →
     `LINK_REGISTER failed: <bl_strerror(st)>`
   - deliver error → `LINK_DELIVER failed: <bl_strerror(st)>`

The error-message map is a small table in the file:

```c
static const char *deliver_err_for(bl_client_t *c, bl_status_t st)
{
    /* If the bridge spoke, prefer its English text. */
    const char *bridge = bl_last_bridge_error(c);
    if (bridge && *bridge) return bridge;
    /* Otherwise, use the library's own status name. */
    return bl_strerror(st);
}
```

### Call flow: `link-geo`

1. **Strip `--json` from argv** at any position; remember as a flag.
   (Requirement 3.13c).
2. **Dispatch on `argv[0]`** (the subcommand).
3. **Reject unknown subcommands** with `unknown subcommand: <sub>` + exit 1.
4. **For each subcommand**, call the appropriate `bl_geo_*`, then route
   through the matching `link_geo_print_*` if `--json` is off, or print
   the raw response if `--json` is on.

For `--json` mode, the printers each have a JSON branch that re-serializes
the `bl_geo_*` output struct to a JSON object matching the bridge's
response shape. **Alternative considered, rejected**: capturing the bridge's
exact JSON response bytes through a libBrightLink "raw response" pass-through
API. Rejected because it leaks bridge wire format into the public library
surface and forces libBrightLink to retain the parsed-but-not-yet-formatted
JSON across the call.

The chosen design re-serializes from the typed struct. The format is
deterministic by inspection of the libBrightLink struct fields, and a
golden-output test in the test-harness (Requirement 7) confirms the
re-serialized JSON matches the pre-migration raw-response output for every
verb. If the bridge ever adds a new field that's not in the struct, the
field is dropped from the JSON output — and the test-harness catches that
on the next run.

### `link_geo_print_*` implementations

Each printer is ~15 lines. Example for `link_geo_print_status`:

```c
static void link_geo_print_status(const bl_geo_status_t *s, int json)
{
    if (json) {
        printf("{\"alive\":%s,\"engine_kind\":\"%s\","
               "\"fix_age_seconds\":%g,\"accuracy_m\":%g}\n",
               s->alive ? "true" : "false", s->engine_kind,
               s->fix_age_seconds, s->accuracy_m);
        return;
    }
    /* Plain mode (Requirement 3.4): one line per field, fixed order, omit
     * fields whose values are sentinel-absent. */
    printf("alive: %s\n", s->alive ? "true" : "false");
    if (s->engine_kind[0])        printf("engine_kind: %s\n", s->engine_kind);
    if (s->fix_age_seconds >= 0)  printf("fix_age_seconds: %g\n", s->fix_age_seconds);
    if (!isnan(s->accuracy_m))    printf("accuracy_m: %g\n", s->accuracy_m);
}
```

The "absent" sentinel for each field is picked when the libBrightLink v0.2
`bl_geo_*_t` struct is designed (above): `0`/`""` for strings, `-1` for
seconds counters that are positive in normal use, `NAN` for accuracies. The
printer treats those values as "skip this line" (Requirement 3.4–3.8).

### Argument validation (Requirement 3.13)

All validation lives in the builtin handlers, before the libBrightLink call:

- `bsh-inject`: token-by-token scan; both `--type` and `--context` must
  appear; unknown tokens rejected.
- `link-geo proximity`: zone arg required, length ≤ 256.
- `link-geo refresh`: `--timeout` defaults to `30`; `strtol` must consume
  the entire token; value must be in `[1, 300]`.
- `link-geo get`: `--format` defaults to `wgs84`; must be one of
  `wgs84`, `brightspace`, `both`.
- `link-geo` itself: empty `argv[0]` (no subcommand) → print usage banner
  + exit 1 (Requirement 3.12).

### Error message preservation (Requirement 3.11)

Pre-migration error strings are preserved verbatim. They live as string
literals in the appropriate handler at the appropriate failure point. A
table comment at the top of `Src/Modules/brightlink.c` lists every
preserved string with a one-line rationale, so future readers don't
"clean them up" by paraphrasing.

### `LINK_BUF_MAX` (Requirement 3.11 stdin overflow)

Preserved at the pre-migration value (`64 * 1024`) as a `#define` near the
top of the file. The numeric literal in the error string is constructed at
compile time:

```c
#define LINK_BUF_MAX (64 * 1024)
#define _STR(x) #x
#define _XSTR(x) _STR(x)
static const char STDIN_OVERFLOW_MSG[] =
    "stdin read failed or exceeded " _XSTR(LINK_BUF_MAX) " bytes";
```

## Build System (Requirement 2)

### `configure.ac` changes

```m4
# ─── REPLACE the existing AC_CHECK_LIB([crypto]) and AC_CHECK_LIB([secp256k1])
#     blocks (currently around lines 858-869). They are no longer needed here;
#     libBrightLink links them transitively.

# ─── NEW: --with-libbrightlink=<submodule|system|auto>
AC_ARG_WITH([libbrightlink],
  [AS_HELP_STRING([--with-libbrightlink=ARG],
    [How to obtain libBrightLink: submodule, system, or auto (default)])],
  [with_libbrightlink="$withval"],
  [with_libbrightlink=auto])

case "$with_libbrightlink" in
  submodule|system|auto) ;;
  *) AC_MSG_ERROR([--with-libbrightlink must be one of: submodule, system, auto]) ;;
esac

# Probe system first under auto and system:
brightlink_found_system=no
if test "$with_libbrightlink" != "submodule"; then
  PKG_CHECK_MODULES([BRIGHTLINK], [brightlink >= 0.2],
    [brightlink_found_system=yes],
    [
      AC_CHECK_LIB([brightlink], [bl_client_new],
        [AC_CHECK_HEADER([brightlink/brightlink.h],
          [brightlink_found_system=yes
           BRIGHTLINK_LIBS="-lbrightlink"
           BRIGHTLINK_CFLAGS=""],
          [])],
        [])
    ])
fi

# Pick path:
brightlink_path=""
if test "$with_libbrightlink" = "system"; then
  if test "$brightlink_found_system" = "no"; then
    AC_MSG_ERROR([--with-libbrightlink=system but no system libBrightLink found.
Install a libBrightLink package providing brightlink.pc, or use
--with-libbrightlink=submodule and run:
  git submodule update --init subprojects/libbrightlink])
  fi
  brightlink_path="system"
elif test "$with_libbrightlink" = "submodule" || test "$brightlink_found_system" = "no"; then
  if test ! -f "$srcdir/subprojects/libbrightlink/meson.build"; then
    AC_MSG_ERROR([No system libBrightLink found and submodule is missing.
Run:  git submodule update --init subprojects/libbrightlink
Or install a system libBrightLink package providing brightlink.pc.])
  fi
  brightlink_path="submodule"
else
  brightlink_path="system"
fi

AC_SUBST([BRIGHTLINK_PATH], [$brightlink_path])
AC_SUBST([BRIGHTLINK_CFLAGS])
AC_SUBST([BRIGHTLINK_LIBS])
```

### Makefile fragment for `Src/Modules/brightlink.c`

The bsh build system uses per-module Makefile fragments. The brightlink
module's fragment is updated to honor `$(BRIGHTLINK_PATH)`:

```make
ifeq ($(BRIGHTLINK_PATH),submodule)
  BRIGHTLINK_BUILDDIR := $(builddir)/subprojects/libbrightlink
  BRIGHTLINK_CFLAGS   := -I$(srcdir)/../../subprojects/libbrightlink/include
  BRIGHTLINK_LIBS     := $(BRIGHTLINK_BUILDDIR)/libbrightlink.a

  $(BRIGHTLINK_BUILDDIR)/libbrightlink.a:
	mkdir -p $(BRIGHTLINK_BUILDDIR)
	cd $(BRIGHTLINK_BUILDDIR) && \
	  meson setup --buildtype=release --default-library=static \
	    $(srcdir)/../../subprojects/libbrightlink
	ninja -C $(BRIGHTLINK_BUILDDIR)

  brightlink.so: $(BRIGHTLINK_BUILDDIR)/libbrightlink.a
endif

# In both paths, prepend the include flag so #include <brightlink/brightlink.h>
# resolves to our copy first:
brightlink_CPPFLAGS := $(BRIGHTLINK_CFLAGS) $(brightlink_CPPFLAGS)
brightlink_LIBS     := $(BRIGHTLINK_LIBS) $(brightlink_LIBS)
```

The `$(BRIGHTLINK_LIBS)` already includes the transitive `-lcrypto`
`-lsecp256k1` through libBrightLink's own pkg-config (`Libs.private`).

## Pin Storage Policy (Requirement 6)

`bl_pin_store_memory()` is the only constructor allowed. Decision rationale:

- bsh is a long-lived interactive shell, not a single-shot tool. Pin
  continuity inside one session is what users want; cross-session
  persistence isn't what bsh users expect from an interactive shell.
- Disk persistence requires a durable home for the file, which raises
  XDG-spec questions (which directory? what permissions on first creation?
  cleanup on `--rm-rf-home`?). All of those questions exist for bsh-iputils
  too, where the answer is `~/.brightchain/iputils-pins/`. bsh punts on the
  question by not persisting at all — defensible because re-pinning at
  shell start is cheap (one prompt during the shell's first BrightLink
  builtin invocation, never again in that session).
- Memory-only is *enforceable*: every disk-write code path (`bl_pin_store_file`,
  `bl_pin_store_custom` with a writing vtable) is forbidden by Requirement
  6.2/6.3. A reviewer can grep for those names with confidence.

**Alternative considered, rejected**: `bl_pin_store_file()` under
`$XDG_STATE_HOME/bsh/brightlink-pins/`. Rejected because (a) bsh doesn't
otherwise touch `$XDG_STATE_HOME`, so introducing a write there for one
feature is a footgun, and (b) the security model of disk-pinning depends
on the pin file mode being 0600 and the directory mode being 0700 on every
container, sandbox, and remote shell where bsh might run; getting that
universally right is more work than memory-only is worth.

## Session Lifetime (Requirement 5)

The `bl_client_t` is a per-shell-process singleton. Lifecycle:

- Created lazily on first `bsh-inject` or `link-geo` invocation
  (Requirement 5.3, the chosen lazy-vs-eager option).
- Reused across every subsequent invocation until the module unloads
  (Requirement 5.4).
- Freed in `finish_` (Requirement 5.6), only if non-NULL (Requirement 5.7).

**Lazy-vs-eager rationale**: shells where `bsh-inject` and `link-geo` are
never called pay zero BrightLink cost. A `bsh -c 'echo hi'` startup
shouldn't open a Unix socket to BrightNexus. Lazy is the pre-migration
behavior and Requirement 5.3 enforces it.

**Failure recovery**: if `bl_client_new()` returns NULL on the first call,
`bsh_link_client_g` stays NULL, the current builtin invocation fails with
exit 1, and the next builtin invocation tries again (Requirement 5.5).
This handles transient out-of-memory conditions without permanently breaking
the module.

**Re-registration**: when a session expires, libBrightLink's lazy
re-register (Requirement 1.7) fires inside the next verb call — bsh doesn't
explicitly retry. Requirement 5.13 forbids the bsh module from doing its
own retry loop on `BL_ERR_NOT_REGISTERED`.

**`zmodload -u && zmodload`**: the unload calls `finish_`, which frees the
client and NULLs the global. The reload starts with `bsh_link_client_g ==
NULL`, so the next builtin gets a fresh handshake (Requirement 5.8). This
is the same code path as a bsh process that just started.

## Test-Harness Continuity (Requirement 7)

### Baseline capture (Requirement 7.6)

Before the rewrite commit, the migration branch's first commit captures
vitest JSON reporter output for all four suites running against the
**pre-migration** `bsh` binary:

```sh
yarn test:against-real-brightnexus --reporter=json > test-baselines/against-real-brightnexus.json
yarn test:against-real-bsh         --reporter=json > test-baselines/against-real-bsh.json
yarn test:against-real-client      --reporter=json > test-baselines/against-real-client.json
yarn test:unit                     --reporter=json > test-baselines/unit.json
git add test-baselines/ && git commit -m "test-harness: capture pre-migration baselines"
```

The four files are committed to the branch. The CI then verifies post-
migration runs report `passed` for every test that's `passed` in those
baselines (Requirement 7.1–7.4).

### Mock-seam migration (Requirement 7.4–7.5)

The unit suite's pre-migration mocks attach to a Unix-domain-socket at the
syscall level. Post-migration, the same tests can either:

a) **Keep the socket-level mock**: BrightNexus mock continues to terminate
   real socket connections; libBrightLink talks to it as if it were the
   real bridge. Most tests don't need to change.

b) **Move to a `bl_client_t`-level mock**: replace the libBrightLink call
   with a stub that records `(verb, args)` tuples. Faster, more focused,
   but requires rewiring each test.

The chosen approach is **(a) for everything that already works at the
socket level, (b) only for new tests added during the migration**. This
minimizes test changes and keeps the migration commit's diff focused on
`Src/Modules/brightlink.c`.

### Skip/todo discipline (Requirement 7.7)

The migration branch's CI fails if any test moves from `passed` to
`skipped` or `todo`. This is enforced by a small script that diffs the
baseline JSON against the post-migration JSON.

## Migration Sequence (Requirement 8)

### Commit ordering

1. **`libBrightLink v0.2.0`** (in `Digital-Defiance/libbrightlink` repo,
   not in bsh):
   - Implements all of Requirement 1.
   - Tagged with `v0.2.0` annotated tag.
   - All v0.1 tests still pass.
   - New `tests/test_v02_verbs.c` covers the new surface.
   - Pushed to upstream before any bsh commit references it.

2. **`bsh: capture pre-migration baselines`** (on bsh migration branch):
   - Adds `test-baselines/*.json` (Requirement 7.6).
   - No source changes.

3. **`bsh: add libBrightLink as submodule`** (Requirement 8.2a):
   - Adds `.gitmodules` with the path/url.
   - Adds `subprojects/libbrightlink/` gitlink at exact `v0.2.0` SHA
     (Requirement 8.4).
   - No other source changes.
   - Pre-migration `Src/Modules/brightlink.c` still compiles and runs.

4. **`bsh: configure --with-libbrightlink wiring`** (Requirement 8.2b):
   - `configure.ac` and Makefile fragment changes per the section above.
   - `Src/Modules/brightlink.c` unchanged — still using its in-module
     protocol implementation. The module compiles against the new
     `BRIGHTLINK_LIBS` but doesn't yet *use* libBrightLink for anything.
   - `-lcrypto` and `-lsecp256k1` removed from the link line; the symbols
     are now satisfied transitively through libBrightLink's pkg-config
     `Libs.private`.

5. **`bsh: rewrite Src/Modules/brightlink.c against libBrightLink`**
   (Requirement 8.2c, 8.5):
   - Touches *only* `Src/Modules/brightlink.c` and its build-generated
     companion files.
   - Implements every Requirement 3, 4, 5, 6 acceptance criterion.
   - Includes the pre-migration error-string preservation table.
   - The diff is large but the touch surface is intentionally narrow.

6. **`bsh: cleanup`** (optional, Requirement 8.2d):
   - Removes any helpers the rewrite no longer needs.

### Revert path

`git revert <SHA-of-rewrite-commit>` returns `Src/Modules/brightlink.c` to
its pre-migration content. The submodule and build-system commits stay in
place. The reverted module no longer needs libBrightLink at runtime, but
the linker still finds it (the in-module crypto code re-enables itself).
The build still passes; the test-harness still passes.

This is the property that makes the migration safe to land: if libBrightLink
turns out to need fixes after the migration ships, we can revert just the
rewrite without losing the v0.2 surface work or the build-system wiring.

## Open Questions Resolved During Spec Authoring

- **Lazy vs eager `bsh_link_client_g`**: lazy. (See Session Lifetime above.)
- **Memory-only vs file pin store**: memory-only. (See Pin Storage Policy.)
- **Mock seam migration strategy**: keep socket-level for existing tests,
  move new tests to `bl_client_t`-level. (See Test-Harness Continuity.)
- **JSON output for `--json` mode**: re-serialize from typed struct, not
  pass-through from bridge. (See Call flow: `link-geo`.)
- **`LINK_BUF_MAX` placement**: `#define` in `Src/Modules/brightlink.c`,
  preserved at pre-migration value. Numeric literal in error string is
  constructed via stringification macro so the two never drift.

## Open Questions Deferred to Implementation

- **`libBrightLink v0.2` branch name in upstream repo**: `v0.2.x` per
  Requirement 2.1. Concrete branch name is the implementer's call (`main`
  could remain v0.1.x while a `v0.2.x` branch carries v0.2 work, or v0.2
  could land on `main` and v0.1.x is preserved by tag only). The spec
  does not constrain this — only the commit SHA the bsh submodule points
  at.
- **`bl_geo_zone_t.zone_id` length**: spec'd as `char zone_id[128]` here.
  If implementation discovers a real zone id longer than 127 chars in the
  bridge's data, escalate before changing the struct (changing it post-tag
  would violate Requirement 1.10).
- **`bl_push_subscription_t` opaque struct**: implementation-defined; the
  public header just declares the typedef-of-incomplete-type.
