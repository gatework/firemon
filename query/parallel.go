package query

import (
	"runtime"
	"sync"
)

// maxWorkers bounds the evaluations run at once: each splits address sets
// into many short-lived pieces, and more workers raise the peak memory
// faster than they cut the time.
const maxWorkers = 4

// Each runs f for 0..n-1 on up to maxWorkers goroutines and returns when
// all are done. f must only write state of its own index: callers merge
// the results in index order afterwards, so the outcome does not depend
// on scheduling.
func Each(n int, f func(i int)) {
	workers := min(n, runtime.GOMAXPROCS(0), maxWorkers)
	if workers <= 1 {
		for i := range n {
			f(i)
		}
		return
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				f(i)
			}
		})
	}
	for i := range n {
		next <- i
	}
	close(next)
	wg.Wait()
}
