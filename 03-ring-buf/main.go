package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

//	type gdata struct {
//		Pid      uint32
//		FileName string
//	}
const MaxDataSizeBash = 400

type Event struct {
	Pid uint32
	Len uint16
	Buf [MaxDataSizeBash]byte
}

func decode(e Event, payload []byte) (newE Event, err error) {
	newE = e
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &newE.Pid); err != nil {
		log.Println("1111")
		return
	}
	// if err = binary.Read(buf, binary.LittleEndian, &newE.Fd); err != nil {
	// 	return
	// }
	if err = binary.Read(buf, binary.LittleEndian, &newE.Len); err != nil {
		log.Println("2222")
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
	fmt.Println(payload[0:])
	fmt.Println(payload[6:])
	if err = binary.Read(buf, binary.LittleEndian, &newE.Buf); err != nil {
		log.Printf("3333: pid: %d len: %d \n", newE.Pid, newE.Len)
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
	binaryPath := "/lib/x86_64-linux-gnu/libssl.so.3"
	// binaryPath := "/lib/x86_64-linux-gnu/libnode.so.72"
	// binaryPath := "/var/lib/docker/overlay2/d0a7b64b6210683fe3a18eb4cda77951b978eec5d34dc81d7650673108898948/diff/usr/local/bin/node"
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
	progWriteEx, err := bpfModule.GetProgram("uprobe_ssl_write_ex")
	if err != nil {
		panic(err)
	}
	offsetWriteEx, err := helpers.SymbolToOffset(binaryPath, "SSL_write_ex")
	if err != nil {
		panic(err)
	}
	if _, err := progWriteEx.AttachUprobe(-1, binaryPath, offsetWriteEx); err != nil {
		panic(err)
	}

	progReadEx, err := bpfModule.GetProgram("uprobe_ssl_read_ex")
	if err != nil {
		panic(err)
	}
	offsetReadEx, err := helpers.SymbolToOffset(binaryPath, "SSL_read_ex")
	if err != nil {
		panic(err)
	}
	if _, err := progReadEx.AttachUprobe(-1, binaryPath, offsetReadEx); err != nil {
		panic(err)
	}

	progWrite, err := bpfModule.GetProgram("uprobe_ssl_write")
	if err != nil {
		panic(err)
	}
	offsetWrite, err := helpers.SymbolToOffset(binaryPath, "SSL_write")
	if err != nil {
		panic(err)
	}
	if _, err := progWrite.AttachUprobe(-1, binaryPath, offsetWrite); err != nil {
		panic(err)
	}

	progRead, err := bpfModule.GetProgram("uprobe_ssl_read")
	if err != nil {
		panic(err)
	}
	offsetRead, err := helpers.SymbolToOffset(binaryPath, "SSL_read")
	if err != nil {
		panic(err)
	}
	if _, err := progRead.AttachUprobe(-1, binaryPath, offsetRead); err != nil {
		panic(err)
	}
	if _, err := progRead.AttachUprobe(-1, binaryPath, offsetRead); err != nil {
		panic(err)
	}

	progRetRead, err := bpfModule.GetProgram("probe_ret_SSL_read")
	if err != nil {
		panic(err)
	}
	if _, err := progRetRead.AttachURetprobe(-1, binaryPath, offsetRead); err != nil {
		panic(err)
	}

	progRetReadEx, err := bpfModule.GetProgram("probe_ret_SSL_read_ex")
	if err != nil {
		panic(err)
	}
	if _, err := progRetReadEx.AttachURetprobe(-1, binaryPath, offsetReadEx); err != nil {
		panic(err)
	}
	// if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
	// 	panic(err)
	// }
	// eventsChannel := make(chan []byte)
	// pb, err := bpfModule.InitRingBuf("events", eventsChannel)
	// if err != nil {
	// 	panic(err)
	// }
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
			// var event Event
			// event, err := decode(event, e)
			// if err != nil {
			// 	fmt.Println("decode:", err)
			// 	continue
			// }
			// fmt.Println(len(e))
			pid := binary.LittleEndian.Uint32(e[0:4])
			len := binary.LittleEndian.Uint16(e[4:6])
			buf := string(bytes.TrimRight(e[6:], "\x00"))
			// gd := gdata{
			// 	Pid:      pid,
			// 	FileName: fileName,
			// }
			// log.Printf("pid %d opened %q", gd.Pid, gd.FileName)
			log.Printf("pid: %d len: %d buf: %s", pid, len, buf)
			// log.Printf("pid: %d len: %d buf: %s", event.Pid, event.Len, event.Buf)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		}
	}
}
