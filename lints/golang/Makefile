# Makefile for lint sources

SHELL:=/bin/bash

PATH_GOPATH=.go
PATH_GOCACHE=.gocache

SRCS := $(wildcard *.go)
PROGS := $(patsubst %.go,%,$(SRCS))

all: $(PROGS)

clean:
	rm -vf $(PROGS)

list:
	@grep -Po '^[^#[:space:]|SHELL|PATH|$$][a-zA-Z].*(?=\:)' Makefile | sort

%: %.go
	@echo "Compiling Go script $< to $(patsubst %.go,%,$<) ..."; \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go build -v -x -o $(patsubst %.go,%,$<) $^
