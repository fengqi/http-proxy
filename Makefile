SHELL := /bin/bash

GOCMD=go
GOBUILD=$(GOCMD) build -i

.PHONY: all build
default: build
all: build

build:
	CGO_ENABLED=0 $(GOBUILD) -ldflags "-w -s" -v -o proxy main.go
