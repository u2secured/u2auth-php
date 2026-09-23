#!/usr/bin/env bash
# Lints every file under a src/ directory with `php -l` on a real PHP 7.4 CLI
# (via Docker). Defaults to this SDK's own src/; pass a directory argument to
# point it at another PHP-7.4-floor codebase in this repo (e.g. the WordPress
# plugin's src/, which has no bin/ of its own and reuses this script).
#
# Why this exists: PHPCompatibility (see phpcs.xml.dist) is a static heuristic
# and, as of the 9.3.5 release this SDK pins, has no sniffs at all for most
# PHP 8.0+ syntax (nullsafe operator, enums, readonly properties, constructor
# promotion, union types, match, never). Every one of those is a genuine
# *parse* error on 7.4, so running the real 7.4 parser is a complete, exact
# check rather than a heuristic one -- it cannot miss a syntax-level
# incompatibility the way the sniff can.
#
# tests/ is deliberately excluded: it uses PHP 8 syntax (PHPUnit attributes)
# and is never shipped.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${1:-$SCRIPT_DIR/../src}"
PHP74_IMAGE="php:7.4-cli"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required to run the PHP 7.4 syntax gate (bin/check-php74-syntax.sh) but was not found on PATH." >&2
  echo "This check refuses to silently skip -- install/enable Docker rather than bypassing it." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: the Docker daemon is not reachable (docker info failed)." >&2
  echo "This check refuses to silently skip -- start Docker rather than bypassing it." >&2
  exit 1
fi

if [ ! -d "$SRC_DIR" ]; then
  echo "ERROR: expected source directory not found: $SRC_DIR" >&2
  exit 1
fi

# Resolve to an absolute path. `docker run -v` rejects a relative host path
# ("includes invalid characters for a local volume name ... use absolute
# path") and `find` below emits paths relative to whatever SRC_DIR was
# passed in, so a relative caller (e.g. CI invoking this against the
# WordPress plugin's src/ with a repo-root-relative argument) would fail
# every file with a false syntax error. This SDK's own default
# ($SCRIPT_DIR/../src) is already absolute, which is why that case alone
# never surfaced this.
SRC_DIR="$(cd "$SRC_DIR" && pwd)"

# Avoid `mapfile` (bash 4+ only) so this also runs under macOS's stock
# /bin/bash (3.2). A while-loop fed by process substitution, rather than a
# pipe, keeps FAILED/COUNT visible outside the loop instead of a subshell.
FAILED=0
COUNT=0

while IFS= read -r -d '' FILE; do
  COUNT=$((COUNT + 1))
  # Relative to SRC_DIR itself (not SCRIPT_DIR/../) so this reads sensibly
  # whether SRC_DIR is this SDK's own default or an external directory
  # argument.
  REL_PATH="${FILE#"$SRC_DIR"/}"
  if ! OUTPUT=$(docker run --rm -v "$FILE:/probe.php:ro" "$PHP74_IMAGE" php -l /probe.php 2>&1); then
    echo "PHP 7.4 SYNTAX ERROR in $REL_PATH:" >&2
    echo "$OUTPUT" >&2
    FAILED=1
  fi
done < <(find "$SRC_DIR" -type f -name '*.php' -print0 | sort -z)

if [ "$COUNT" -eq 0 ]; then
  echo "ERROR: no .php files found under $SRC_DIR -- refusing to report success on an empty check." >&2
  exit 1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "PHP 7.4 syntax gate FAILED: one or more files under src/ do not parse on PHP 7.4." >&2
  exit 1
fi

echo "PHP 7.4 syntax gate: $COUNT file(s) OK."
