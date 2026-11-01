#!/usr/bin/env python3
"""Alternate immutable benchmark binaries; exact paired sign-flip comparison."""
import datetime,hashlib,itertools,json,math,os,pathlib,platform,re,statistics,subprocess
root=pathlib.Path(__file__).resolve().parent
pattern=re.compile(r'^(Benchmark\S+)\s+\d+\s+([\d.]+) ns/op.*?([\d.]+) B/op\s+([\d.]+) allocs/op')
samples=json.loads((root/'samples.json').read_text())
for variant in samples:
 for key in samples[variant]:samples[variant][key]=samples[variant][key][:9]
env=dict(os.environ,GOMAXPROCS='4')
for variant in samples:
 p=root/(variant+'.txt');sections=p.read_text().split('goos:');assert len(sections)==11;p.write_text('goos:'.join(sections[:10]))
for i in range(9,10):
 for variant in (('before','after') if i%2==0 else ('after','before')):
  result=subprocess.run([str(root/(variant+'.test')),'-test.run=^$','-test.bench=Benchmark(Parse|Scan|FortinetTopology)','-test.benchtime=200ms','-test.count=1','-test.benchmem'],env=env,capture_output=True,text=True,check=True)
  with (root/(variant+'.txt')).open('a') as f:f.write(result.stdout)
  for line in result.stdout.splitlines():
   m=pattern.match(line)
   if m:samples[variant].setdefault(m[1],[]).append(list(map(float,m.groups()[1:])))
 print('completed pair',i+1,flush=True)
rows=[]
for name,before in sorted(samples['before'].items()):
 after=samples['after'][name]
 assert len(before)==len(after)==10,(name,len(before),len(after))
 diffs=[math.log(a[0]/b[0]) for a,b in zip(after,before)]
 observed=abs(sum(diffs));extreme=sum(abs(sum(x*s for x,s in zip(diffs,signs)))>=observed-1e-12 for signs in itertools.product((-1,1),repeat=10))
 b=[statistics.median(v[j] for v in before) for j in range(3)]
 a=[statistics.median(v[j] for v in after) for j in range(3)]
 rows.append({'benchmark':name,'before':b,'after':a,'change_percent':[(y/x-1)*100 for x,y in zip(b,a)],'paired_time_p':extreme/1024})
(root/'samples.json').write_text(json.dumps(samples,indent=2)+'\n');(root/'comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
lines=['| Benchmark | time change | B/op change | allocs/op change | paired p |','| --- | ---: | ---: | ---: | ---: |']
for row in rows:lines.append('| '+row['benchmark']+' | '+' | '.join(f'{v:+.2f}%' for v in row['change_percent'])+f" | {row['paired_time_p']:.4f} |")
(root/'comparison.md').write_text('\n'.join(lines)+'\n')
metadata={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.platform(),'go':subprocess.check_output(['go','version'],text=True).strip(),'GOMAXPROCS':4,'pairs':10,'benchtime':'200ms','baseline':'full working tree including preceding uncommitted Hillstone refinement; git HEAD 19d1fb999feb63a2f5cf7c2450dec1e7e63da01a','last_pair_rerun':'Pair 10 rerun after adapter tests ended to avoid known CPU contention; replacement selected before inspecting rerun results', 'method':'Alternating serial processes; reported medians; exact two-sided paired log-time sign-flip p (1024 sign permutations), exploratory not adjusted for multiple comparisons','binary_sha256':{v:hashlib.sha256((root/(v+'.test')).read_bytes()).hexdigest() for v in samples}}
(root/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
regressed=[r['benchmark'] for r in rows if r['change_percent'][0]>5 and r['paired_time_p']<0.05]
print('significant time regressions above 5%:',regressed,flush=True)
