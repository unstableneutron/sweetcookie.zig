# sweetcookie.zig

## Project overview

`sweetcookie.zig` is a Zig-native cookie extraction library and CLI. It reads
cookies from inline JSON, Firefox profiles, Safari `Cookies.binarycookies`, and
Chromium-family `Cookies` SQLite databases, then writes Lightpanda JSON,
`sweet-cookie-json`, or an RFC 6265 `Cookie` header.

The CLI is a thin wrapper over the library API in `src/root.zig`; applications
can import the package as `sweetcookie` and call `sweetcookie.get`.

## Installation

Build the library and CLI with Zig:

```sh
zig build
```

The binary is installed at `zig-out/bin/sweetcookie`.

## Library usage

```zig
const std = @import("std");
const sweetcookie = @import("sweetcookie");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var options = sweetcookie.Options{};
    options.inline_input.json =
        \\[{"name":"sid","value":"1","domain":"example.com","path":"/"}]
    ;

    const result = try sweetcookie.get(allocator, options);
    defer result.deinit(allocator);

    for (result.cookies) |cookie| {
        std.debug.print("{s} for {s}\n", .{ cookie.name, cookie.domain });
    }
}
```

## CLI usage

### Export cookies

```sh
PROFILE="$(mktemp -d "$(pwd)/tests/fixtures/readme-inline.XXXXXX")"
trap 'rm -rf "$PROFILE"' EXIT
cat >"$PROFILE/cookies.json" <<'JSON'
[
  {"name":"sid","value":"one","domain":".example.com","path":"/","expires":4102444800},
  {"name":"theme","value":"dark","domain":"example.com","path":"/app","secure":true}
]
JSON
./zig-out/bin/sweetcookie export \
  --inline-file "$PROFILE/cookies.json" \
  --format lightpanda-json >/dev/null
```

### Print a Cookie header

```sh
PROFILE="$(mktemp -d "$(pwd)/tests/fixtures/readme-header.XXXXXX")"
trap 'rm -rf "$PROFILE"' EXIT
cat >"$PROFILE/cookies.json" <<'JSON'
[
  {"name":"sid","value":"one","domain":".example.com","path":"/","expires":4102444800},
  {"name":"admin","value":"nope","domain":"other.example","path":"/"}
]
JSON
./zig-out/bin/sweetcookie header \
  --inline-file "$PROFILE/cookies.json" \
  --url https://example.com/ >/dev/null
```

### Print the CLI version

```sh
./zig-out/bin/sweetcookie version | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' >/dev/null
```

### Chromium broad export with `--all-domains`

Chromium broad exports require explicit `--all-domains` opt-in. This example
uses an isolated fixture profile under `tests/fixtures/`, not a real browser
profile.

```sh
PROFILE="$(mktemp -d "$(pwd)/tests/fixtures/readme-chrome.XXXXXX")"
trap 'rm -rf "$PROFILE"' EXIT
sqlite3 "$PROFILE/Cookies" <<'SQL'
CREATE TABLE cookies(
  creation_utc INTEGER NOT NULL DEFAULT 0,
  host_key TEXT NOT NULL,
  top_frame_site_key TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  encrypted_value BLOB NOT NULL,
  path TEXT NOT NULL,
  expires_utc INTEGER NOT NULL,
  is_secure INTEGER NOT NULL,
  is_httponly INTEGER NOT NULL,
  last_access_utc INTEGER NOT NULL DEFAULT 0,
  has_expires INTEGER NOT NULL DEFAULT 1,
  is_persistent INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 1,
  samesite INTEGER NOT NULL DEFAULT -1,
  source_scheme INTEGER NOT NULL DEFAULT 0,
  source_port INTEGER NOT NULL DEFAULT -1,
  is_same_party INTEGER NOT NULL DEFAULT 0,
  last_update_utc INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta(key, value) VALUES('version', '23');
INSERT INTO cookies(host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly)
VALUES('.example.com', 'sid', 'fixture-value', X'', '/', 13350000000000000, 0, 0);
SQL
./zig-out/bin/sweetcookie export \
  --browser chrome \
  --chrome-cookies-db "$PROFILE/Cookies" \
  --all-domains \
  --format lightpanda-json >/dev/null
```

## Cookie model semantics

The canonical cookie model keeps both normalized and source-domain information:

- `domain` is normalized and never includes a leading dot.
- `raw_domain` preserves the exact source domain, including any leading dot.
- `host_only` is `true` when the source domain did not start with a dot.
- `path`, `expires`, `secure`, `http_only`, and `same_site` are preserved in
  the common model used by every backend.
- Duplicate cookies are keyed by `(name, normalized domain, exact path)` and
  resolved deterministically by the selected merge mode.

## Security notes

- Raw cookie values are redacted from warnings and debug logs; stderr never
  prints cookie values.
- `--output` writes through an atomic temp file and sets the final file mode to
  `0600` on POSIX systems.
- Real browser default-path discovery is opt-in. Set
  `SWEETCOOKIE_ALLOW_REAL_BROWSER=1` only when you intentionally want to read a
  real profile.
- Browser backends snapshot-copy profile files and sidecars before parsing. The
  source profile is opened read-only for stat/snapshot purposes, then parsing
  happens from the copy so fixture and live profile bytes remain unchanged.
