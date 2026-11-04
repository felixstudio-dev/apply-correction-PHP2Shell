"""Validate only public package artifacts; never ingest host inventory or credentials."""
import hashlib
import json
import pathlib
import sys
import tarfile

work = pathlib.Path(sys.argv[1])
revision, version, fixture, compiler = sys.argv[2:]
image = json.loads((work / "checks/image-inspect.json").read_text())[0]
assert image["Os"] == "linux" and image["Architecture"] == "amd64"
config = image["Config"]
assert config["User"] == "65532:65532"
assert config["Entrypoint"] == ["/usr/local/bin/php2shell-fix"]
assert config["Cmd"] == ["scan", "--json"]
assert not config.get("Volumes") and not config.get("ExposedPorts")
labels = config["Labels"]
assert labels["org.opencontainers.image.source"] == "https://github.com/felixstudio-dev/apply-correction-PHP2Shell"
assert labels["org.opencontainers.image.revision"] == revision
assert labels["org.opencontainers.image.version"] == version

no_php = json.loads((work / "checks/no-php.json").read_text())
assert no_php["status"] == "NO_PHP_CLI_FOUND" and no_php["installations"] == []
scan = json.loads((work / "checks/php-scan.json").read_text())
assert scan["status"] == "ASSESSMENT_ONLY" and len(scan["installations"]) == 1
runtime = scan["installations"][0]
assert runtime["version"] == "8.4.27" and runtime["sapi"] == "cli"
assert not runtime.get("error") and runtime["executable"] == "/usr/local/bin/php"

allowed = {
    "usr/local/bin/php2shell-fix",
    "usr/share/licenses/php2shell-fix/LICENSE",
    "usr/share/licenses/php2shell-fix/THIRD-PARTY-NOTICES.txt",
    "usr/share/doc/php2shell-fix/README.md",
}
# Docker adds these container runtime files at create/export, not to the image layer.
runtime_files = {".dockerenv", "etc/hostname", "etc/hosts", "etc/resolv.conf"}
with tarfile.open(work / "checks/rootfs.tar") as archive:
    entries = list(archive)
    def safe_name(entry):
        name = entry.name
        if name.startswith('./'):
            name = name[2:]
        path = pathlib.PurePosixPath(name)
        assert name and not path.is_absolute() and '..' not in path.parts, f'Unsafe archive path: {entry.name}'
        assert entry.isfile() or entry.isdir(), f'Unexpected entry type: {entry.name}'
        assert not entry.mode & 0o7000, f'Special file mode: {entry.name}'
        return str(path)
    normalized = [safe_name(entry) for entry in entries]
    assert len(normalized) == len(set(normalized)), 'Duplicate archive entries'
    members = [entry for entry in entries if not entry.isdir()]
    assert all(entry.isfile() for entry in members), "Unexpected links or special files"
    paths = {safe_name(entry) for entry in members}
    assert allowed <= paths and paths <= allowed | runtime_files, paths
    binary_member = next(entry for entry in members if safe_name(entry) == "usr/local/bin/php2shell-fix")
    assert binary_member.mode & 0o777 == 0o555

binary_hash = hashlib.sha256((work / "context/php2shell-fix").read_bytes()).hexdigest()
receipt = {
    "source_revision": revision,
    "version": version,
    "platform": "linux/amd64",
    "compiler": compiler,
    "binary_sha256": binary_hash,
    "image_id": image["Id"],
    "php_fixture": fixture,
    "validation": ["go test ./...", "go vet ./...", "static ELF amd64", "non-root read-only no-network negative fixture", "real PHP CLI 8.4.27 read-only scan", "rootfs allowlist", "extracted binary hash"],
    "limitations": "CLI_ONLY; no PHP bundled; no host, web-worker, mitigation or package-upgrade validation",
}
(work / "output/receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt, indent=2))
