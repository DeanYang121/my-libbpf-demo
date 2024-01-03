package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	Pid      uint32
	Ret      uint32
	FileName [256]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tpEnter.Close()
	tpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tpExit.Close()

	log.Println("Waiting for events...")
	time.Sleep(time.Minute * 1024)
}
