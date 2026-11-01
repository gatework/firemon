from pathlib import Path
import os, subprocess
root = Path(__file__).parent
args = ['-test.run=^$', '-test.bench=^BenchmarkParse$/(hillstone|huawei)$', '-test.benchtime=200ms', '-test.count=1', '-test.cpu=4']
env = dict(os.environ, GOMAXPROCS='4', GOWORK='off', GOPROXY='off')
for label in ('before','after'):
    (root / (label + '.txt')).write_text('')
for sample in range(10):
    labels = ('before','after') if sample % 2 == 0 else ('after','before')
    for label in labels:
        with (root / (label + '.txt')).open('a') as output:
            subprocess.run([str(root / ('benchmarks-' + label + '.test')), *args], stdout=output, stderr=subprocess.STDOUT, env=env, check=True)
    print('sample', sample + 1, 'complete', flush=True)
