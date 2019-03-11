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
VERBOSITY=0

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

exit_script()
{
  # Default exit code is 1
  local exit_code=1
  local re var

  re='^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
  if echo "$1" | egrep -q "$re"; then
    exit_code=$1
    shift
  fi

  re='[[:alnum:]]'
  if echo "$@" | egrep -iq "$re"; then
    if [ $exit_code -eq 0 ]; then
      print_green "INFO: $@"
    else
      print_red "ERROR: $@" 1>&2
    fi
  fi

  # Print 'aborting' string if exit code is not 0
  [ $exit_code -ne 0 ] && echo >&2 "Aborting script..."

  exit $exit_code
}

usage()
{
    # Prints out usage and exit.
    sed -e "s/^    //" -e "s|SCRIPT_NAME|$(basename $0)|" <<"    EOF"
    USAGE

    Install required packages and build all third-party certificate linters
    used by the 'lint.sh' wrapper.

    SYNTAX
            SCRIPT_NAME [OPTIONS]

    OPTIONS

     -c, --clean             Clean all downloaded and compiled objects.

     --no-install-missing    Do not install missing packages.

     -v, --verbose           Make the script more verbose.
     -h, --help              Prints this usage.

    EOF

    exit_script $@
}

test_arg()
{
  # Used to validate user input
  local arg="$1"
  local argv="$2"

  if [ -z "$argv" ]; then
    if echo "$arg" | egrep -q '^-'; then
      usage "Null argument supplied for option $arg"
    fi
  fi

  if echo "$argv" | egrep -q '^-'; then
    usage "Argument for option $arg cannot start with '-'"
  fi
}

# get the root directory this script is running from
# if the script is called from a symlink, the link is
# resolved to the absolute path.
function get_root_dir()
{
  source="${BASH_SOURCE[0]}"
  # resolve $source until the file is no longer a symlink
  while [ -h "${source}" ]; do
    dir=$( cd -P "$( dirname "${source}" )" && pwd )
    source=$(readlink "${source}")
    # if $source was a relative symlink, we need to resolve it
    # relative to the path where the symlink file was located
    [[ ${source} != /* ]] && source="${dir}/${source}"
  done
  dir="$( cd -P "$( dirname "${source}" )" && pwd )"
  echo ${dir}
  return
}

function install_pkg()
{
  pkg_name="$1"

  if [ -z "${pkg_name}" ]; then
    exit_script 1 "Package name not provided to check script."
  fi

  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package."
      exit_script 1 "You need to install ${pkg_name}. Aborting."
    else
      sudo_cmd="sudo"
    fi
  fi

  if [ "${INSTALL_MISSING}" == "true" ]; then
    if hash apt-get 2>/dev/null; then
      print_yellow "Installing missing package '${pkg_name}' via apt-get ..."
      if ! ${sudo_cmd} apt-get install -V -y ${pkg_name}; then
        exit_script 1 "Failed to install package '${pkg_name}'."
      fi
      return
    fi
  fi

  exit_script 1 "You need to install ${pkg_name}. Aborting."
}

DIR=$(get_root_dir)
MAKE_ARG="all"

# process arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--clean)
      MAKE_ARG="clean"
      shift
    ;;
    --no-install-missing)
      INSTALL_MISSING="false"
      shift
    ;;
    -h|--help)
      usage
    ;;
    -v|--verbose)
      ((VERBOSITY++))
      shift
    ;;
    *)
      usage
      shift
    ;;
  esac
done

if [ ${VERBOSITY} -gt 0 ]; then
  MAKE_ARG="--debug=v ${MAKE_ARG}"
fi

# Check for missing packages
hash openssl 2>/dev/null || { install_pkg "openssl"; }
hash go 2>/dev/null || { install_pkg "golang-go"; }
hash git 2>/dev/null || { install_pkg "git"; }

# Update sub-modules
if ! git submodule init; then
  exit_script 1 "Failed to initialize required modules."
fi
if ! git submodule update --recursive; then
  exit_script 1 "Failed to update required modules."
fi

# Build all modules
if ! make ${MAKE_ARG}; then
  exit_script 1 "Failed to build required modules."
fi

exit_script 0
