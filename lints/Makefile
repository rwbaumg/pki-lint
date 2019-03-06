# Makefile for lint sources

SHELL:=/bin/bash

all:
	pushd x509lint && ${MAKE} all && popd;
	pushd ev-checker && ${MAKE} all && popd;
	pushd aws-certlint/ext && ruby extconf.rb && ${MAKE} all && popd;
	mkdir ./.gpkg && export GOPATH=$(realpath ./.gpkg) && \
	go get -u -v github.com/globalsign/certlint/asn1 && \
	go get -u -v github.com/globalsign/certlint/certdata && \
	go get -u -v github.com/globalsign/certlint/checks && \
	go get -u -v github.com/globalsign/certlint/errors && \
	go get -u -v github.com/globalsign/certlint/checks/certificate/all && \
	go get -u -v github.com/globalsign/certlint/checks/extensions/all && \
	go get -u -v github.com/cloudflare/cfssl/log && \
	go get -u -v github.com/cloudflare/cfssl/revoke && \
	go get -u -v github.com/golang/groupcache/lru && \
	go get -u -v github.com/pkg/profile && \
	pushd gs-certlint && \
        go build -v && \
	popd

clean:
	pushd x509lint && ${MAKE} clean && popd;
	pushd ev-checker && ${MAKE} clean && popd;
	pushd aws-certlint/ext && ${MAKE} clean && popd;
	pushd gs-certlint && go clean -v && popd && rm -rv ./.gpkg;
