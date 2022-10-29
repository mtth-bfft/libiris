#!/usr/bin/env python3

import json
import shutil
import sys
from pathlib import Path

target_dir = Path(sys.argv[1])
for line in sys.stdin:
    try:
        obj = json.loads(line)
    except:
        continue
    if type(obj) is not dict or obj.get('executable', None) is None:
        continue
    if 'test' in obj.get('target', {}).get('kind', []):
        shutil.copy(obj['executable'], target_dir)
    elif 'bin' in obj.get('target', {}).get('kind', []):
        shutil.copy(obj['executable'], target_dir / 'workers')
