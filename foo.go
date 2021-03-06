//go:build linux
// +build linux

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type foo struct {
	VfsReadEntry *ebpf.Program `ebpf:"vfs_read_entry"`
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := foo{}
	spec, err := ebpf.LoadCollectionSpec("./foo.bpf.o")
	if err != nil {
		log.Fatalf("loadFoo: %v", err)
	}

	// Creating the map works
	//mount_ns_set, err := ebpf.NewMap(&ebpf.MapSpec{
	//	Type:       ebpf.Hash,
	//	KeySize:    8,
	//	ValueSize:  4,
	//	MaxEntries: 1024,
	//})
	//if err != nil {
	//	log.Fatalf("create my map: %s", err)
	//}

	// loading from pinned doesn't work
	mount_ns_set, err := ebpf.LoadPinnedMap("/sys/fs/bpf/mount_ns_set", nil)
	if err != nil {
		log.Fatalf("load my map: %s", err)
	}

	spec.RewriteMaps(map[string]*ebpf.Map{
		"mount_ns_set": mount_ns_set,
	})

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	kpread, err := link.Kprobe("vfs_read", objs.VfsReadEntry)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpread.Close()

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
