#!/bin/bash
# Builds sources for the certificate linter

hash openssl 2>/dev/null || { echo >&2 "You need to install OpenSSL (openssl). Aborting."; exit 1; }
hash go 2>/dev/null || { echo >&2 "You need to install Golang (gccgo-go). Aborting."; exit 1; }
hash git 2>/dev/null || { echo >&2 "You need to install Git (git). Aborting."; exit 1; }

# Update sub-modules
if ! git submodule init; then
  echo >&2 "ERROR: Failed to initialize required modules."
  exit 1
fi
if ! git submodule update --recursive; then
  echo >&2 "ERROR: Failed to update required modules."
  exit 1
fi

if ! make; then
  echo >&2 "ERROR: Failed to build required modules."
  exit 1
fi

exit 0
