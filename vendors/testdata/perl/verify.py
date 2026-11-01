#!/usr/bin/env python3
"""Rerun bounded Perl oracles; optionally compare the selected Go checkout.

Only synthetic stdin is passed to the reference, with no network or write mount.
Expected results remain read-only; failures are not accepted as new goldens.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True, help='Perl backend directory containing lib/Firewall')
parser.add_argument('--image', default='algosec-dev-app:latest')
parser.add_argument('--go-root', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
results = []
for vendor in ('hillstone', 'huawei', 'fortinet', 'srx', 'netscreen', 'asa'):
    expected = json.loads((root / (vendor + '.json')).read_text())
    command = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--entrypoint', 'perl', '-i',
               '-v', str(args.source.resolve()) + ':/source:ro', '-v', str(root) + ':/oracle:ro',
               args.image, '-I/source/lib', '/oracle/reference.pl', vendor]
    actual = subprocess.run(command, input=(root / (vendor + '.cfg')).read_bytes(), capture_output=True, timeout=60, check=True)
    if actual.stderr or json.loads(actual.stdout) != expected:
        raise SystemExit(vendor + ': Perl reference differs: ' + actual.stderr.decode())
    row = {'vendor': vendor, 'perl': 'matched'}
    if args.go_root:
        actual = subprocess.run(['go', 'run', str(root / 'go_probe.go'), vendor, str(root / (vendor + '.cfg'))],
                                cwd=args.go_root, env=dict(os.environ, GOWORK='off', GOPROXY='off'),
                                capture_output=True, timeout=60, check=True)
        if json.loads(actual.stdout) != expected:
            raise SystemExit(vendor + ': Go result differs')
        if actual.stderr.decode().strip() != 'complete: true diagnostics: []':
            raise SystemExit(vendor + ': Go graph incomplete: ' + actual.stderr.decode())
        row['go'] = 'matched and complete'
    results.append(row)
print(json.dumps(results, indent=2))
