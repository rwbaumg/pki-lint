#!/bin/bash
# Builds sources for the certificate linter

# Update sub-modules
if ! git submodule update --recursive; then
  echo >&2 "ERROR: Failed to initialize required modules."
  exit 1
fi

if ! make; then
  echo >&2 "ERROR: Failed to build required modules."
  exit 1
fi

exit 0
