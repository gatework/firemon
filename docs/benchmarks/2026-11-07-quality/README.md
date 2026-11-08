# 本轮质量整改基准

环境：Apple M5，darwin/arm64，Go 1.27.1，GOMAXPROCS=1。
每项 200 ms、六次采样，前后版本串行运行并交替执行顺序；计时期间不运行其他测试。
benchstat 使用本地已缓存的 golang.org/x/perf 版本
`v0.0.0-20261009192801-be2c69fb417e`。

before 为本轮开始时的未提交工作树快照，after 为最终实现，不代表两个发布版本。
两侧使用相同的新增 AddressSet 基准和同一份测试辅助函数。
CatalogExactReuse 原夹具缺少当前复用契约要求的声明名称；两侧共同补齐名称，保留
复用对象、成本和变更结果断言。生产代码没有因该夹具修改而变化。
关键源文件及共享夹具摘要见 [source-hashes.json](source-hashes.json)。

从两份源码分别构建测试二进制，交替执行六轮：

```sh
go test -c -o address.test ./flow
go test -c -o routes.test ./benchmarks
go test -c -o plan.test ./plan
GOMAXPROCS=1 ./address.test -test.run='^$' -test.bench='^BenchmarkAddressSet$' -test.benchtime=200ms -test.benchmem -test.cpu=1
GOMAXPROCS=1 ./routes.test -test.run='^$' -test.bench='^BenchmarkRouteResolution$' -test.benchtime=200ms -test.benchmem -test.cpu=1
GOMAXPROCS=1 ./plan.test -test.run='^$' -test.bench='^Benchmark(PlanCandidates|CatalogExactReuse)$' -test.benchtime=200ms -test.benchmem -test.cpu=1
```

- [区间前后比较](address-benchstat.txt)：[before](address-before.txt)、[after](address-after.txt)。
- [路由前后比较](routes-benchstat.txt)：[before](routes-before.txt)、[after](routes-after.txt)。
- [计划前后比较](plan-benchstat.txt)：[before](plan-before.txt)、[after](plan-after.txt)。

全部样本为合成数据；微基准不代表生产吞吐量或设备执行性能。
