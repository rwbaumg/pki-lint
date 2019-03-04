# Makefile for lint sources

SHELL:=/bin/bash

all:
	pushd x509lint && ${MAKE} all && popd && \
	pushd ev-checker && ${MAKE} all && popd && \
	pushd aws-certlint/ext && ruby extconf.rb && ${MAKE} all && popd
clean:
	pushd x509lint && ${MAKE} clean && popd && \
	pushd ev-checker && ${MAKE} clean && popd && \
	pushd aws-certlint/ext && ${MAKE} clean && popd
