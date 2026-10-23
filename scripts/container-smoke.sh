#!/usr/bin/env bash
# Smoke-test a built ControlLoop container image.
#
# Usage: scripts/container-smoke.sh <image reference>
#
# Run by `.github/workflows/ci.yml` on every pull request and by
# `.github/workflows/release.yml` before an image is pushed. It proves,
# against the real image:
#
#   1. the image runs as a non-root user;
#   2. the image carries no build toolchain (no uv, pip, gcc, cc or make);
#   3. `controlloop --version` works;
#   4. a real `controlloop scan` of a synthetic fixture completes with the
#      container's network disabled (`--network none`), so no network
#      request is part of scanning;
#   5. a `gate` against a mounted git repository resolves its baseline
#      (git is present and the mount's ownership is accepted) and writes
#      its evidence into the mount, run as the host user (`--user`), the
#      way the documentation tells a Linux user to run it: the image's
#      own uid (10001) owns nothing on the host, so a writable mount
#      needs the caller's uid.
#
# Every check is a hard failure. Nothing here needs a published release.
set -euo pipefail

IMAGE="${1:?usage: container-smoke.sh <image reference>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "--- 1. runs as a non-root user"
uid="$(docker run --rm --network none --entrypoint id "$IMAGE" -u)"
if [ "$uid" = "0" ]; then
  echo "image runs as root (uid 0)" >&2
  exit 1
fi
echo "uid=$uid"

echo "--- 2. no build toolchain in the image"
for tool in uv pip gcc cc make; do
  if docker run --rm --network none --entrypoint sh "$IMAGE" -c "command -v $tool" >/dev/null 2>&1; then
    echo "image contains $tool, which a runtime image must not" >&2
    exit 1
  fi
done
echo "none of uv, pip, gcc, cc, make is present"

echo "--- 3. --version"
docker run --rm --network none "$IMAGE" --version

echo "--- 4. real scan with networking disabled"
mkdir -p "$WORK/fixture"
printf '%s' '{"name": "report-agent", "skills": [{"id": "read-quarterly-metrics", "name": "read-quarterly-metrics"}]}' \
  > "$WORK/fixture/agent-card.json"
docker run --rm --network none -v "$WORK/fixture:/work:ro" "$IMAGE" scan /work --format json \
  > "$WORK/report.json"
python3 - "$WORK/report.json" <<'EOF'
import json, sys
report = json.load(open(sys.argv[1]))
verdict = report["verdict"]
print(f"verdict={verdict}")
sys.exit(0 if verdict == "passed" else 1)
EOF

echo "--- 5. gate against a mounted git repository"
mkdir -p "$WORK/repo"
cp "$WORK/fixture/agent-card.json" "$WORK/repo/"
git -C "$WORK/repo" init -q -b main
git -C "$WORK/repo" -c user.name=smoke -c user.email=smoke@example.invalid add -A
git -C "$WORK/repo" -c user.name=smoke -c user.email=smoke@example.invalid commit -q -m "fixture"
# The mount is writable so `gate` can write its evidence artifact, and
# the container runs as the host user so it may write there.
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$WORK/repo:/work" "$IMAGE" \
  gate /work --default-branch main --evidence-path /work/evidence.json --format json \
  > "$WORK/gate.json" || status=$?
status="${status:-0}"
# 0 (pass) and 3 (incomplete, nothing blocking) are both fine for a
# one-file fixture; anything else means the container could not gate.
case "$status" in
  0|3) echo "gate exit $status" ;;
  *) echo "gate exited $status" >&2; cat "$WORK/gate.json" >&2; exit 1 ;;
esac
test -s "$WORK/repo/evidence.json"
echo "evidence written"

echo "container smoke test passed for $IMAGE"
