# Makefile for lint sources

SHELL:=/bin/bash

all:
	pushd x509lint && ${MAKE} all && popd;
	pushd ev-checker && ${MAKE} all && popd;
	pushd aws-certlint/ext && ruby extconf.rb && ${MAKE} all && popd;
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/asn1 && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/certdata && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/checks && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/errors && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/checks/certificate/all && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/globalsign/certlint/checks/extensions/all && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/cloudflare/cfssl/log && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/cloudflare/cfssl/revoke && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/golang/groupcache/lru && \
	GOPATH=$(abspath ./.gpkg) go get -u -v github.com/pkg/profile && \
	pushd gs-certlint && \
        GOPATH=$(abspath ./.gpkg) go build -x -v && \
	popd

clean:
	pushd x509lint && ${MAKE} clean && popd;
	pushd ev-checker && ${MAKE} clean && popd;
	pushd aws-certlint/ext && ${MAKE} clean && popd;
	pushd gs-certlint && GOPATH=$(abspath ../.gpkg) go clean -x -v && popd && \
	if [ -e "./.gpkg" ]; then rm -rfv ./.gpkg; fi
