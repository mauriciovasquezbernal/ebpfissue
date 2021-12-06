all: foo foo.bpf.o

foo: foo.bpf.o foo.go
	go build .

foo.bpf.o: bpf/foo.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c bpf/foo.bpf.c -o foo.bpf.o

clean:
	rm foo foo.bpf.o