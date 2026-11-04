#!/bin/zsh
# Exercise the real installed vendor archive, using a disposable APFS copy.
set -eu
setopt PIPE_FAIL
readonly REPO_ROOT="${0:A:h:h}"
/usr/bin/python3 - "$REPO_ROOT/engine/patch-deep-link.py" \
    "${DOPPEL_PRIMARY_APP:-/Applications/ChatGPT.app}/Contents/Resources/app.asar" <<'PY'
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('patcher', sys.argv[1])
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)
source = Path(sys.argv[2])
print('Doppel startup-adapter QA')
try:
    p.verify(source)
except p.PatchError:
    print('  ✓ the original vendor app has no Doppel adapter')
else:
    raise AssertionError('the primary app unexpectedly contains the adapter')
original = p.read_archive(source)
with tempfile.TemporaryDirectory(prefix='doppel-routing-') as scratch:
    target = Path(scratch) / 'app.asar'
    subprocess.run(['/bin/cp', '-c', str(source), str(target)], check=True)
    header_hash = p.patch(target)
    assert p.verify(target) == header_hash
    print('  ✓ the current vendor archive installs and verifies without source matching')
    assert p.patch(target) == header_hash
    print('  ✓ repeated installation is idempotent')
    adapted = p.read_archive(target)
    files = {m.path: m for m in p.members(adapted)}
    count = 0
    for member in p.members(original):
        if member.path == 'package.json':
            continue
        assert p.read_member(original, member) == p.read_member(adapted, files[member.path]), member.path
        count += 1
    print(f'  ✓ all {count} vendor members remain byte-identical')
print('4 passed, 0 failed')
PY
