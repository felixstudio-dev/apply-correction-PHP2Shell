"""Synthetic regression fixtures for the package rootfs allowlist, not PHP tests."""
import io
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest


class ValidationTests(unittest.TestCase):
    def validate(self, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for path in ('checks', 'context', 'output'):
                (root / path).mkdir()
            (root / 'context/php2shell-fix').write_bytes(b'fixture')
            image = {'Os': 'linux', 'Architecture': 'amd64', 'Config': {
                'User': '65532:65532', 'Entrypoint': ['/usr/local/bin/php2shell-fix'], 'Cmd': ['scan', '--json'],
                'Labels': {'org.opencontainers.image.source': 'https://github.com/felixstudio-dev/apply-correction-PHP2Shell', 'org.opencontainers.image.revision': 'revision', 'org.opencontainers.image.version': 'version'}}}
            (root / 'checks/no-php.json').write_text(json.dumps({'status': 'NO_PHP_CLI_FOUND', 'installations': []}))
            (root / 'checks/php-scan.json').write_text(json.dumps({'status': 'ASSESSMENT_ONLY', 'installations': [{'version': '8.4.27', 'sapi': 'cli', 'executable': '/usr/local/bin/php'}]}))
            paths = ['usr/local/bin/php2shell-fix', 'usr/share/licenses/php2shell-fix/LICENSE', 'usr/share/licenses/php2shell-fix/THIRD-PARTY-NOTICES.txt', 'usr/share/doc/php2shell-fix/README.md']
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode='w') as archive:
                for path in paths:
                    entry = tarfile.TarInfo(path)
                    entry.mode = 0o555 if path.endswith('/php2shell-fix') else 0o444
                    entry.size = 1
                    archive.addfile(entry, io.BytesIO(b'x'))
                if extra is not None:
                    archive.addfile(extra)
            layer_bytes = layer.getvalue()
            config_bytes = json.dumps({'rootfs': {'diff_ids': ['sha256:' + hashlib.sha256(layer_bytes).hexdigest()]}}).encode()
            image['Id'] = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
            (root / 'checks/image-inspect.json').write_text(json.dumps([image]))
            manifest = [{'RepoTags': ['php2shell-package:test'], 'Config': 'config.json', 'Layers': ['layer.tar']}]
            with tarfile.open(root / 'output/image.tar', 'w') as archive:
                for name, contents in [('manifest.json', json.dumps(manifest).encode()), ('config.json', config_bytes), ('layer.tar', layer_bytes)]:
                    entry = tarfile.TarInfo(name)
                    entry.size = len(contents)
                    archive.addfile(entry, io.BytesIO(contents))
            return subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('validate.py')), directory, 'revision', 'version', 'fixture', 'compiler'], capture_output=True).returncode

    def test_valid_allowlist(self):
        self.assertEqual(self.validate(), 0)

    def test_reject_traversal(self):
        self.assertNotEqual(self.validate(tarfile.TarInfo('../../usr/local/bin/php2shell-fix')), 0)

    def test_reject_absolute_path(self):
        self.assertNotEqual(self.validate(tarfile.TarInfo('/usr/local/bin/php2shell-fix')), 0)

    def test_reject_duplicate(self):
        self.assertNotEqual(self.validate(tarfile.TarInfo('usr/local/bin/php2shell-fix')), 0)

    def test_reject_symlink(self):
        entry = tarfile.TarInfo('usr/local/bin/link')
        entry.type = tarfile.SYMTYPE
        entry.linkname = 'php2shell-fix'
        self.assertNotEqual(self.validate(entry), 0)

    def test_reject_traversal_directory(self):
        entry = tarfile.TarInfo('../outside')
        entry.type = tarfile.DIRTYPE
        self.assertNotEqual(self.validate(entry), 0)

    def test_reject_unlisted_file(self):
        self.assertNotEqual(self.validate(tarfile.TarInfo('etc/unexpected')), 0)


if __name__ == '__main__':
    unittest.main()
