GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOGENERATE=$(GOCMD) generate

BINARY_NAME=ebpf_lb

all: help

## help: show this help message
.PHONY: help
help: Makefile
	@echo
	@echo " Choose a make command to run"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## build: build the binary
.PHONY: build
build: generate
	$(GOBUILD) -o $(BINARY_NAME) -v

## clean: clean the binary and generated files
.PHONY: clean
clean: 
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	find "$(CURDIR)" -name "*_bpfe?.go" -delete

## generate: generate the bpf code
.PHONY: generate
generate:
	$(GOGENERATE)