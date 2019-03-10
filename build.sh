#!/bin/bash
#
# [0x19e Networks]
# Copyright (c) 2019 Robert W. Baumgartner
#
# PROJECT : pki-lint x509 certificate linter
# AUTHOR  : Robert W. Baumgartner <rwb@0x19e.net>
# LICENSE : MIT License
#
## DESCRIPTION
#
# This script is used to compile required linting modules used by
# this project.
#
## USAGE
#
# Run this script from the root directory:
# `./build.sh`
#
# Afterwards, you can run `./lint.sh --help` for usage information.
#
## LICENSE
#
# MIT License
#
# Copyright (c) 2019 Robert W. Baumgartner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

INSTALL_MISSING="true"
NO_COLOR="false"

print_green()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e "\x1b[39;49;00m\x1b[32;01m${1}\x1b[39;49;00m"
  else
  echo "${1}"
  fi
}

print_red()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[31;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
}

print_yellow()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[33;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
}

function install_pkg()
{
  pkg_name="$1"

  if [ -z "${pkg_name}" ]; then
    print_red "ERROR: Package name not provided to check script."
    exit 1
  fi

  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package."
      print_red "You need to install ${pkg_name}. Aborting."
      exit 1
    else
      sudo_cmd="sudo"
    fi
  fi

  if [ "${INSTALL_MISSING}" == "true" ]; then
    if hash apt-get 2>/dev/null; then
      print_yellow "Installing missing package '${pkg_name}' via apt-get ..."
      if ! ${sudo_cmd} apt-get install -V -y ${pkg_name}; then
        print_red "ERROR: Failed to install package '${pkg_name}'."
        exit 1
      fi
      return
    fi
  fi

  print_red "You need to install ${pkg_name}. Aborting."
  exit 1
}

hash openssl 2>/dev/null || { install_pkg "openssl"; }
hash go 2>/dev/null || { install_pkg "golang-go"; }
hash git 2>/dev/null || { install_pkg "git"; }

# Update sub-modules
if ! git submodule init; then
  print_red "ERROR: Failed to initialize required modules."
  exit 1
fi
if ! git submodule update --recursive; then
  print_red "ERROR: Failed to update required modules."
  exit 1
fi

if ! make; then
  print_red "ERROR: Failed to build required modules."
  exit 1
fi

exit 0
