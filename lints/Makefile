# Makefile for lint sources

SHELL:=/bin/bash

BIN_NAME=bin
PATH_GOPATH=./golang/.go
PATH_GOCACHE=./golang/.gocache

# Determine the major and minor Go version numbers to construct path.
GO_VERSION=`GOROOT='' go version | head -n1 | grep -Po '(?<=\sgo)[0-9]+\.[0-9]+(?=(\s|\.))'`
PATH_GOROOT=/usr/lib/go-$(GO_VERSION)

# Configure static Go script settings
GOLANG_PATH := golang/
GOLANG_SRCS := $(wildcard ${GOLANG_PATH}*.go)
GOLANG_PROGS := $(patsubst ${GOLANG_PATH}%.go,${GOLANG_PATH}%,$(GOLANG_SRCS))

all: x509lint ev-checker aws-certlint gs-certlint zlint golang bin

list:
	@grep -Po '^[^#[:space:]|SHELL|PATH|$$][a-zA-Z].*(?=\:)' Makefile | sort

test:
	@echo "GO_VERSION='${GO_VERSION}'"
	@echo "GOROOT='${PATH_GOROOT}'"
	@echo "GOPATH='$(abspath ${PATH_GOPATH})'"
	@echo "GOCACHE='$(abspath ${PATH_GOCACHE})'"

clean:
	rm -vf $(GOLANG_PROGS);
	pushd x509lint && ${MAKE} clean && popd;
	pushd ev-checker && ${MAKE} clean && popd;
	pushd gs-certlint && GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go clean -x && popd;
	pushd aws-certlint/ext && ${MAKE} clean && popd;
	pushd zlint && GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) ${MAKE} clean && popd;
	if [ -e "${PATH_GOCACHE}" ]; then rm -rfv "${PATH_GOCACHE}"; fi;
	if [ -e "./${BIN_NAME}" ]; then rm -rfv "./${BIN_NAME}"; fi;
	if [ -e "${PATH_GOPATH}" ]; then rm -rfv "${PATH_GOPATH}"; fi;

bin:
	mkdir -v ./${BIN_NAME}
	ln -sf -v ../x509lint/x509lint-root ${BIN_NAME}
	ln -sf -v ../x509lint/x509lint-int ${BIN_NAME}
	ln -sf -v ../x509lint/x509lint-sub ${BIN_NAME}
	ln -sf -v ../ev-checker/ev-checker ${BIN_NAME}
	ln -sf -v ../gs-certlint/gs-certlint ${BIN_NAME}
	ln -sf -v ../zlint/zlint ${BIN_NAME}
	ln -sf -v ../zlint/zlint-gtld-update ${BIN_NAME}

golang: $(GOLANG_PROGS)

golang/%: ${GOLANG_PATH}%.go
	@echo "Compiling Go script $< to $(patsubst ${GOLANG_PATH}%.go,${GOLANG_PATH}%,$<) ..."; \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go build -x -v -o $(patsubst ${GOLANG_PATH}%.go,${GOLANG_PATH}%,$<) $<

zlint: zlint/zlint zlint/zlint-gtld-update

x509lint: x509lint/x509lint-root x509lint/x509lint-int x509lint/x509lint-sub

ev-checker: ev-checker/ev-checker

gs-certlint: gs-certlint/gs-certlint

aws-certlint: aws-certlint/ext/asn1validator.so

x509lint/%:
	pushd x509lint && ${MAKE} all && popd;

ev-checker/%:
	pushd ev-checker && ${MAKE} all && popd;

aws-certlint/%:
	pushd aws-certlint/ext && ruby extconf.rb && ${MAKE} all && popd;

gs-certlint/%:
	pushd gs-certlint && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/asn1 && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/certdata && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/checks && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/errors && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/checks/certificate/all && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/globalsign/certlint/checks/extensions/all && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/cloudflare/cfssl/log && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/cloudflare/cfssl/revoke && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/golang/groupcache/lru && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go get -u -v github.com/pkg/profile && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) go build -a -x -v && \
	popd;

zlint/%:
	pushd zlint && \
	GOPATH=$(abspath ${PATH_GOPATH}) GOCACHE=$(abspath ${PATH_GOCACHE}) ${MAKE} && \
	popd;
