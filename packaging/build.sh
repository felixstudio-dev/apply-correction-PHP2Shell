#!/usr/bin/env bash
set -euo pipefail

source_dir="$(realpath "$1")"
work_dir="$2"
tooling_dir="$(cd "$(dirname "$0")" && pwd)"
python3 "$tooling_dir/test_validation.py"
expected_revision=7a0600ecd84bc32c817d9cb55d6d59976d2331e9
version=v0.1.0-alpha.1
php_fixture='php:8.4.27-cli-bookworm@sha256:dd0e2b902f1edfb6ca02fbcb391c28b1554c7d35a4e36e5925876b90aa804851'
test_image=php2shell-package:test

test "$(git -C "$source_dir" rev-parse HEAD)" = "$expected_revision"
test -z "$(git -C "$source_dir" status --porcelain)"
mkdir -p "$work_dir/context" "$work_dir/output" "$work_dir/checks"
context="$work_dir/context"

cd "$source_dir"
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$context/php2shell-fix" ./cmd/php2shell-fix
file "$context/php2shell-fix" | grep -q 'ELF 64-bit.*x86-64.*statically linked'
cp LICENSE "$context/LICENSE"
cp "$tooling_dir/Dockerfile" "$context/Dockerfile"
cp "$tooling_dir/PACKAGE-README.md" "$context/PACKAGE-README.md"
{
  printf 'Go runtime and standard library\n\n'
  cat "$(go env GOROOT)/LICENSE"
  printf '\n\ngolang.org/x/sys v0.49.0\n\n'
  cat "$(go list -m -f '{{.Dir}}' golang.org/x/sys)/LICENSE"
  for patents in "$(go env GOROOT)/PATENTS" "$(go list -m -f '{{.Dir}}' golang.org/x/sys)/PATENTS"; do
    if test -f "$patents"; then printf '\n\nPatent grant\n\n'; cat "$patents"; fi
  done
} > "$context/THIRD-PARTY-NOTICES.txt"

docker build --platform linux/amd64 --build-arg "VERSION=$version" --build-arg "REVISION=$expected_revision" -t "$test_image" "$context"
docker image inspect "$test_image" > "$work_dir/checks/image-inspect.json"
docker run --rm --read-only --network=none --cap-drop=ALL --security-opt=no-new-privileges "$test_image" > "$work_dir/checks/no-php.json"

container="$(docker create "$test_image")"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker cp "$container:/usr/local/bin/php2shell-fix" "$work_dir/checks/extracted-binary"
cmp "$context/php2shell-fix" "$work_dir/checks/extracted-binary"
docker rm "$container" >/dev/null
trap - EXIT

cat > "$work_dir/context/Dockerfile.fixture" <<EOF
FROM $test_image AS tool
FROM $php_fixture
COPY --from=tool /usr/local/bin/php2shell-fix /usr/local/bin/php2shell-fix
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/php2shell-fix"]
EOF
docker build --platform linux/amd64 -f "$context/Dockerfile.fixture" -t php2shell-package:php-fixture "$context"
docker run --rm --read-only --network=none --cap-drop=ALL --security-opt=no-new-privileges php2shell-package:php-fixture scan --php /usr/local/bin/php --json > "$work_dir/checks/php-scan.json"

docker save "$test_image" -o "$work_dir/output/image.tar"
python3 "$tooling_dir/validate.py" "$work_dir" "$expected_revision" "$version" "$php_fixture" "$(go version)"
(cd "$work_dir/output" && sha256sum image.tar > image.tar.sha256)
printf 'Verified Linux amd64 OCI distribution of %s at %s.\n' "$version" "$expected_revision"
