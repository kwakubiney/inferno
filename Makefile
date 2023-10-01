#This was copied from https://github.com/lizrice/learning-ebpf/blob/main/chapter8/Makefile

TARGET = firewall
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_OBJ = ${TARGET:=.o}

all: $(TARGET) $(BPF_OBJ) 
.PHONY: all 
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
	rm -f /sys/fs/bpf/$(TARGET)
	tc qdisc add dev eth0 clsact
	tc filter add dev eth0 ingress bpf direct-action obj $(BPF_OBJ) sec tc/ingress
	tc filter add dev eth0 egress bpf direct-action obj $(BPF_OBJ) sec tc/egress

$(BPF_OBJ): %.o: %.c vmlinux.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-g \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h		

clean:
	- tc qdisc del dev eth0 clsact
	- rm -rf /sys/fs/bpf/tc
	- rm $(BPF_OBJ)