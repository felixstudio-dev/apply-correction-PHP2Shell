"""Bounded GHCR metadata checks. No tokens or HTTP headers are logged."""
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

ROOT = 'https://api.github.com/users/felixstudio-dev/packages/container/apply-correction-php2shell'
EXPECTED_REPO = 'felixstudio-dev/apply-correction-PHP2Shell'


def get(path, allow_missing=False):
    request = urllib.request.Request(ROOT + path, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'php2shell-package-verifier',
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404 and allow_missing:
            return None
        raise SystemExit(f'GitHub package metadata request failed: HTTP {error.code}; no alternate credential or permission change will be attempted.') from None


def versions():
    for page in range(1, 101):
        rows = get(f'/versions?per_page=100&page={page}')
        for row in rows:
            yield row
        if len(rows) < 100:
            return
    raise SystemExit('Version listing exceeded its safety bound; refusing publication.')


mode, tag = sys.argv[1:3]
if mode == 'preflight':
    package = get('', allow_missing=True)
    if package is None:
        print('No accessible package metadata exists yet. This is not proof of absence; an authenticated registry check must pass before publication.')
    else:
        for item in versions():
            if tag in item.get('metadata', {}).get('container', {}).get('tags', []):
                raise SystemExit('The requested version tag already exists. Refusing to overwrite it; inspect the existing digest before any retry.')
        print('Package exists, but the requested version tag is unused.')
elif mode == 'verify':
    digest = sys.argv[3]
    package = None
    for attempt in range(3):
        package = get('', allow_missing=True)
        if package is not None:
            break
        if attempt < 2:
            time.sleep(3)
    if package is None:
        receipt_path = pathlib.Path('registry-receipt.json')
        receipt = json.loads(receipt_path.read_text())
        receipt.update({'package_metadata_status': 'pending_visibility_check', 'package_visibility': 'unknown', 'package_url': None})
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        print('Registry publication and binary integrity were verified, but the public package metadata endpoint returned 404. The new package may still be private. Verify package visibility and linkage before claiming public availability; do not repeat the push.')
        sys.exit(0)
    repository = (package.get('repository') or {}).get('full_name')
    assert repository == EXPECTED_REPO, f'Unexpected package repository linkage: {repository}'
    tagged = [item for item in versions() if tag in item.get('metadata', {}).get('container', {}).get('tags', [])]
    assert len(tagged) == 1 and tagged[0]['name'] == digest, 'Published version digest or tag does not match'
    receipt_path = pathlib.Path('registry-receipt.json')
    receipt = json.loads(receipt_path.read_text())
    receipt.update({'package_metadata_status': 'verified', 'package_url': package.get('html_url'), 'package_visibility': package['visibility'], 'linked_repository': repository})
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
else:
    raise SystemExit('Unsupported verification mode')
