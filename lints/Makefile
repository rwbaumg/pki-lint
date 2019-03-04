# Makefile for lint sources

SHELL:=/bin/bash

all:
	pushd x509lint && ${MAKE} all && popd && \
	pushd ev-checker && ${MAKE} all && popd
clean:
	pushd x509lint && ${MAKE} clean && popd && \
	pushd ev-checker && ${MAKE} clean && popd
