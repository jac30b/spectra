.PHONY: gen all build

all: gen build

gen:
	go generate ./ebpf/...

build:
	$(info builing the project...)
	go build