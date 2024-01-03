package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

const MaxDataSizeBash = 256

type Event struct {
	Pid uint32
	// Fd  uint16
	Len uint16
	// Port uint16
	// Addr uint32
	Buf [MaxDataSizeBash]uint8
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

func uint32ToIpV4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip
}

func decode(e Event, payload []byte) (newE Event, err error) {
	newE = e
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &newE.Pid); err != nil {
		return
	}
	// if err = binary.Read(buf, binary.LittleEndian, &newE.Fd); err != nil {
	// 	return
	// }
	if err = binary.Read(buf, binary.LittleEndian, &newE.Len); err != nil {
		return
	}
	// if err = binary.Read(buf, binary.LittleEndian, &newE.Port); err != nil {
	// 	return
	// }
	// if err = binary.Read(buf, binary.LittleEndian, &newE.Count); err != nil {
	// 	return
	// }
	// if err = binary.Read(buf, binary.LittleEndian, &newE.Addr); err != nil {
	// 	return
	// }
	if err = binary.Read(buf, binary.LittleEndian, &newE.Buf); err != nil {
		return
	}
	return
}

func main() {
	// binaryPath := "/lib/x86_64-linux-gnu/libc.so.6"

	// /lib/x86_64-linux-gnu/libnode.so.72
	binaryPath := "/lib/x86_64-linux-gnu/libssl.so.3"
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()
	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("uprobe_ssl_write")
	if err != nil {
		panic(err)
	}
	offset, err := helpers.SymbolToOffset(binaryPath, "SSL_write_ex")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachUprobe(-1, binaryPath, offset); err != nil {
		panic(err)
	}
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
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
			var event Event
			event, err := decode(event, e)
			if err != nil {
				fmt.Println("decode:", err)
				continue
			}
			// fmt.Println(event.Addr)
			// addr := uint32ToIpV4(event.Addr)
			// log.Printf("pid %d fd: %d port: %d ipv4: %s",
			// 	event.Pid, event.Fd, event.Port, addr.String())
			// if len(event.Buf) == 0 {
			// 	continue
			// }
			// buf := unix.ByteSliceToString((event.Buf[:]))
			log.Printf("pid: %d len: %d buf: %s",
				event.Pid, event.Len, unix.ByteSliceToString((event.Buf[:])))
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		}
	}
}
