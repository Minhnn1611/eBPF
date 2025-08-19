BPF_CLANG ?= clang
BPFTOOL   ?= ./bpftool/src/bpftool
LIBBPF_DIR ?= ./libbpf/src/build
LIBBPF_A   := $(LIBBPF_DIR)/libbpf.a
INCLUDES   := -I$(LIBBPF_DIR)/build/usr/include -I./inc

OBJ_DIR    := ./obj
SRC_DIR    := ./src
INC_DIR    := ./inc

BPF_OBJ    := $(OBJ_DIR)/filemon.bpf.o
SKEL_HDR   := $(INC_DIR)/filemon.skel.h
COMMON_HDR := $(INC_DIR)/filemon_common.h
USER_SRC   := $(SRC_DIR)/filemon.c
BPF_SRC    := $(SRC_DIR)/filemon.bpf.c

all: filemon

$(BPF_OBJ): $(BPF_SRC) $(INC_DIR)/vmlinux.h $(COMMON_HDR)
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I$(INC_DIR) \
		-c $< -o $@

$(SKEL_HDR): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

filemon: $(USER_SRC) $(SKEL_HDR) $(COMMON_HDR)
	gcc -O2 -g -Wall $(USER_SRC) -o $@ \
		$(INCLUDES) $(LIBBPF_A) -lelf -lz

clean:
	rm -f filemon $(BPF_OBJ) $(SKEL_HDR)