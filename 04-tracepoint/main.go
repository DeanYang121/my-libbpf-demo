package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	MAX_MSG_SIZE = 256
)

type socketDataEvent struct {
	TimestampNs  uint64
	Pid          uint32
	Fd           int32
	IsConnection bool
	MsgSize      uint32
	Pos          uint64
	Msg          [MAX_MSG_SIZE]uint8
}

func decode(e socketDataEvent, payload []byte) (newE socketDataEvent, err error) {
	newE = e
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &newE.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &newE.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &newE.IsConnection); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &newE.MsgSize); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &newE.Pos); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &newE.Msg); err != nil {
		return
	}
	return
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()
	if err := resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	// accept tracepoint
	progAccept, err := bpfModule.GetProgram("tracepoint_sys_enter_read")
	if err != nil {
		panic(err)
	}
	if _, err := progAccept.AttachTracepoint("syscalls", "sys_enter_read"); err != nil {
		panic(err)
	}

	progAcceptExit, err := bpfModule.GetProgram("tracepoint_sys_exit_read")
	if err != nil {
		panic(err)
	}

	if _, err := progAcceptExit.AttachTracepoint("syscalls", "sys_exit_read"); err != nil {
		panic(err)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	// pb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		panic(err)
	}

	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	for {
		select {
		case e := <-eventsChannel:
			var event socketDataEvent
			event, err := decode(event, e)
			if err != nil {
				fmt.Println("decode err: ", err)
				continue
			}
			log.Printf("Pid: %d Fd: %d isConnect: %v Msg: %s \n", event.Pid, event.Fd, event.IsConnection, event.Msg)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		}
	}
}
