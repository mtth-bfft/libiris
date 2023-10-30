#!/usr/bin/env python3

import json
import shutil
import sys
from pathlib import Path

ARTEFACT_TYPES = ['test', 'bin', 'cdylib']
EXCLUDE_EXTS = ['.pdb']

target_rootdir = Path(sys.argv[1])
for line in sys.stdin:
    try:
        obj = json.loads(line)
    except:
        continue
    if type(obj) is not dict:
        continue
    kinds = obj.get('target', {}).get('kind', [])
    for kind in ARTEFACT_TYPES:
        if kind in kinds:
            break
    else:
        continue
    # We need to give a way for the CI runner to
    # differentiate between actual tests and worker
    # binaries: put them in a subdirectory
    if 'bin' in kinds or 'cdylib' in kinds:
        target_dir = target_rootdir / 'workers'
    else:
        target_dir = target_rootdir
    for filename in obj.get('filenames', []):
        for ext in EXCLUDE_EXTS:
            if filename.lower().endswith(ext):
                break
        else:
            shutil.copy(filename, target_dir)
