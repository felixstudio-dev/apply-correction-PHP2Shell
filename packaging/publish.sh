#!/usr/bin/env bash
set -euo pipefail

artifact_dir="$(realpath "$1")"
image=ghcr.io/felixstudio-dev/apply-correction-php2shell
version=v0.1.0-alpha.1
revision=7a0600ecd84bc32c817d9cb55d6d59976d2331e9
tooling_dir="$(cd "$(dirname "$0")" && pwd)"
test "${GITHUB_REPOSITORY:?}" = 'felixstudio-dev/apply-correction-PHP2Shell'
test "${GITHUB_REF:?}" = 'refs/heads/main'
test "${GITHUB_EVENT_NAME:?}" = 'workflow_dispatch'
test -n "${GH_TOKEN:?}"
test -n "${DOCKER_CONFIG:?}"
mkdir -m 700 -p "$DOCKER_CONFIG"
cd "$artifact_dir"
sha256sum -c image.tar.sha256
python3 - "$revision" "$version" <<'PY'
import json, sys
r = json.load(open('receipt.json'))
assert r['source_revision'] == sys.argv[1] and r['version'] == sys.argv[2]
assert r['platform'] == 'linux/amd64'
PY
docker load -i image.tar
docker image inspect php2shell-package:test > loaded-image.json
python3 - <<'PY'
import json
r = json.load(open('receipt.json'))
i = json.load(open('loaded-image.json'))[0]
assert i['Id'] == r['image_id']
assert i['Config']['Labels']['org.opencontainers.image.revision'] == r['source_revision']
PY

# The job-scoped GITHUB_TOKEN is used only for this repository's registry/API.
# Refuse existing version tags and all authorization failures. Never force or delete.
python3 "$tooling_dir/registry.py" preflight "$version"
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
# A metadata 404 alone is ambiguous. Require an authenticated registry result
# that explicitly identifies an absent manifest; authorization/transport errors stop.
if docker manifest inspect "$image:$version" > existing-manifest.json 2> manifest-check.txt; then
  printf 'Version tag is already present in the registry; refusing to overwrite.\n' >&2
  exit 1
fi
python3 - <<'PY'
import pathlib
message = pathlib.Path('manifest-check.txt').read_text().lower()
ambiguous = ('denied', 'unauthorized', 'forbidden', 'timeout', 'connection', 'tls', 'too many requests')
missing = ('manifest unknown', 'name unknown', 'no such manifest')
if any(word in message for word in ambiguous) or not any(word in message for word in missing):
    raise SystemExit('Registry tag absence was not established. No push was attempted; inspect registry access before retrying.')
print('Authenticated registry reports the requested version manifest absent.')
PY
docker tag php2shell-package:test "$image:$version"
docker push "$image:$version" | tee push-result.txt
digest="$(sed -nE 's/^.*digest: (sha256:[a-f0-9]{64}).*$/\1/p' push-result.txt)"
test "$(printf '%s\n' "$digest" | wc -l)" -eq 1
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
docker pull "$image@$digest"
docker image inspect "$image@$digest" > pulled-image.json
container="$(docker create "$image@$digest")"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker cp "$container:/usr/local/bin/php2shell-fix" pulled-binary
docker rm "$container" >/dev/null
trap - EXIT
python3 - "$digest" <<'PY'
import hashlib, json, sys
r = json.load(open('receipt.json'))
i = json.load(open('pulled-image.json'))[0]
assert i['Id'] == r['image_id'], 'Registry image config does not match tested artifact'
assert hashlib.sha256(open('pulled-binary', 'rb').read()).hexdigest() == r['binary_sha256']
r['registry_digest'] = sys.argv[1]
r['image'] = 'ghcr.io/felixstudio-dev/apply-correction-php2shell:' + r['version']
json.dump(r, open('registry-receipt.json', 'w'), indent=2)
PY
python3 "$tooling_dir/registry.py" verify "$version" "$digest"
cat registry-receipt.json
if test -n "${GITHUB_STEP_SUMMARY:-}"; then
  printf '## Published OCI distribution\n\nImage: `%s:%s`\n\nDigest: `%s`\n\nSource: `%s`\n\nSee registry-receipt.json for visibility and repository linkage. A private package still needs an authorized visibility change before anonymous pulls work.\n' "$image" "$version" "$digest" "$revision" >> "$GITHUB_STEP_SUMMARY"
fi
