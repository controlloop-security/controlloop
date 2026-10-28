#!/usr/bin/env bash
# Check that every commit in a range is signed off by its author under the
# Developer Certificate of Origin (https://developercertificate.org).
#
#   scripts/check-dco.sh <base-sha> <head-sha>
#
# Every non-merge commit reachable from <head-sha> but not from <base-sha>
# must carry a `Signed-off-by:` trailer whose email is the commit author's
# email. `git commit -s` adds exactly that. Exits 1, naming each commit
# that fails, otherwise 0. Used by .github/workflows/dco.yml.
#
# Dependabot is the one exception: it authors commits as its noreply
# address but signs them off as `dependabot[bot] <support@github.com>`, so
# that sign-off also counts on a commit Dependabot authored.
set -euo pipefail

dependabot_author="49699333+dependabot[bot]@users.noreply.github.com"
dependabot_signoff="support@github.com"

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <base-sha> <head-sha>" >&2
  exit 2
fi

base="$1"
head="$2"
checked=0
failed=0

while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  checked=$((checked + 1))
  author_email="$(git log -1 --format='%ae' "$sha")"
  signoff_email="$author_email"
  if [ "$author_email" = "$dependabot_author" ]; then
    signoff_email="$dependabot_signoff"
  fi
  if git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" \
    | grep -qiF -- "<${signoff_email}>"; then
    continue
  fi
  # The subject is left out on purpose: it is free text from the pull
  # request, and the commit id is enough to find it.
  echo "::error::Commit ${sha:0:12} by <${author_email}> has no Signed-off-by line matching its author."
  failed=$((failed + 1))
done < <(git rev-list --no-merges "${base}..${head}")

if [ "$failed" -ne 0 ]; then
  cat <<'EOF'

Every commit must carry a Signed-off-by line from its author, certifying
the Developer Certificate of Origin (https://developercertificate.org).
See CONTRIBUTING.md.

  - New commits:     git commit -s
  - This branch:     git rebase --signoff <base-branch>
                     git push --force-with-lease
EOF
  echo "DCO: ${failed} of ${checked} commit(s) are not signed off by their author."
  exit 1
fi

echo "DCO: all ${checked} commit(s) are signed off by their authors."
