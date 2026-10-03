package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
)

func main() {
	count := 200
	workers := 1
	mode := "success"
	if len(os.Args) > 1 {
		value, err := strconv.Atoi(os.Args[1])
		if err != nil || value < 1 {
			fmt.Fprintln(os.Stderr, "usage: go_exec_probe [positive count] [positive workers] [success|failure]")
			os.Exit(2)
		}
		count = value
	}
	if len(os.Args) > 2 {
		value, err := strconv.Atoi(os.Args[2])
		if err != nil || value < 1 || value > 16 {
			fmt.Fprintln(os.Stderr, "workers must be between 1 and 16")
			os.Exit(2)
		}
		workers = value
	}
	if len(os.Args) > 3 {
		mode = os.Args[3]
	}
	if mode != "success" && mode != "failure" {
		fmt.Fprintln(os.Stderr, "mode must be success or failure")
		os.Exit(2)
	}

	var failures atomic.Int64
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for i := worker + 1; i <= count; i += workers {
				if mode == "failure" {
					path := "/definitely-not-an-edgeos-executable"
					pid, err := syscall.ForkExec(path, []string{path}, &syscall.ProcAttr{
						Files: []uintptr{0, 1, 2},
					})
					if pid > 0 {
						_, _ = syscall.Wait4(pid, nil, 0, nil)
					}
					if errors.Is(err, syscall.ENOENT) {
						continue
					}
					var errno syscall.Errno
					if errors.As(err, &errno) {
						fmt.Printf("worker=%d iteration=%d errno=%d hex=%#x error=%v\n", worker, i, errno, uintptr(errno), err)
					} else {
						fmt.Printf("worker=%d iteration=%d error=%v\n", worker, i, err)
					}
					failures.Add(1)
					continue
				}
				command := exec.Command("/usr/sbin/iptables", "--wait", "-t", "raw", "-L")
				command.Stdout = io.Discard
				command.Stderr = io.Discard
				err := command.Run()
				if err == nil {
					continue
				}
				var errno syscall.Errno
				if errors.As(err, &errno) {
					fmt.Printf("worker=%d iteration=%d errno=%d hex=%#x error=%v\n", worker, i, errno, uintptr(errno), err)
				} else {
					fmt.Printf("worker=%d iteration=%d error=%v\n", worker, i, err)
				}
				failures.Add(1)
			}
		}(worker)
	}
	group.Wait()
	fmt.Printf("attempts=%d workers=%d mode=%s failures=%d\n", count, workers, mode, failures.Load())
	if failures.Load() != 0 {
		os.Exit(1)
	}
}
