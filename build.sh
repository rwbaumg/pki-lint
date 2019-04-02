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

GO_MIN_VERSION=1.3
RUBY_MIN_VERSION=2.1
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

function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

# Adds a package source for Ruby
# This may be required if the distribution does not provide
# a version of Ruby >= v2.1
function add_ruby_src()
{
  # standard ruby: ppa:brightbox/ruby-ng
  if hash apt-get 2>/dev/null; then
    if add_apt_source "brightbox/ruby-ng"; then
      return
    fi
  fi
  exit_script 1 "Failed to configure Ruby package source."
}

# Adds a package source for Golang
# This may be required if the distribution does not provide
# a version of Golang >= v1.3
function add_golang_src()
{
  # standard golang: ppa:gophers/archive
  # newest golang: ppa:longsleep/golang-backports
  if hash apt-get 2>/dev/null; then
    if add_apt_source "gophers/archive"; then
      return
    fi
  fi
  exit_script 1 "Failed to configure Golang package source."
}

# Adds a package source for the system to upgrade packages from
function add_apt_source()
{
  ppa_name="$1"
  if [ -z "${ppa_name}" ]; then
    exit_script 1 "APT PPA name not provided."
  fi

  if [ "${INSTALL_MISSING}" != "true" ]; then
    print_yellow "WARNING: Skipping package source configuration for '$ppa_name'."
    return 1
  fi

  if ! hash apt-get 2>/dev/null; then
    print_yellow "WARNING: Missing apt-get command; cannot configure PPA '$ppa_name'."
    return 1
  fi
  if ! hash add-apt-repository 2>/dev/null; then
    print_yellow "WARNING: Missing add-apt-repository command; cannot configure PPA '$ppa_name'."
    return 1
  fi

  for f in /etc/apt/sources.list.d/*; do
    if ! echo $f | grep -P '\.save$' > /dev/null 2>&1; then
      if [ ! -z "$(grep -ni $ppa_name $f | grep -v -P '^([\s]+)?\#')" ]; then
        print_green "Found custom PPA configuration for package source '$ppa_name'."
        return 0
      fi
    fi
  done

  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package source."
      return 1
    else
      sudo_cmd="sudo"
    fi
  fi

  if [ $VERBOSITY -gt 0 ]; then
    print_yellow "Configuring '$ppa_name' package source for apt-get ..."
  fi

  if ! ${sudo_cmd} add-apt-repository ppa:${ppa_name}; then
    exit_script 1 "Failed to configure '$ppa_name' package source for apt command."
  fi
  if ! ${sudo_cmd} apt-get update; then
    echo >&2 "WARNING: Failed to update apt cache."
    return 1
  fi
  print_green "Added custom package source '$ppa_name' for apt-get."
  return 0
}

# Attempts to install Golang v1.10
function install_golang_v110()
{
  #if hash go 2>/dev/null; then
  #  print_green "Found Golang; 'go' command is in PATH."
  #  return
  #fi

  if [ "${INSTALL_MISSING}" != "true" ]; then
    exit_script 1 "You need to install golang-go >= v1.3; aborting..."
  fi

  install_pkg "golang-1.10-go"

  if [ ! -e "/usr/lib/go-1.10/bin/go" ]; then
    print_red "Golang v1.10 installation failed: missing required file '/usr/lib/go-1.10/bin/go'."
    exit_script 1 "You need to install golang-go >= v1.3; aborting..."
  fi

  #if [ ! -e "/usr/bin/go" ] && [ ! -e "/usr/local/bin/go" ]; then
  if [ ! -e "/usr/local/bin/go" ]; then
    # Check if 'sudo' is required
    sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
      if ! hash sudo 2>/dev/null; then
        print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package."
        exit_script 1 "You need to install sudo. Aborting."
      else
        sudo_cmd="sudo"
      fi
    fi

    #print_yellow "Golang 'go' command is missing from PATH; installing symlink..."
    print_yellow "Creating /usr/local/bin symlink for Golang 'go' command ..."

    # Create a symlink for 'go' command.
    ln_args="-s"
    if [ $VERBOSITY -gt 0 ]; then
      ln_args="-v ${ln_args}"
    fi

    # Symling in /usr/bin
    #if ! ${sudo_cmd} ln ${ln_args} /usr/lib/go-1.10/bin/go /usr/bin/go; then
    #  print_red "Failed to create /usr/bin symlink for /usr/lib/go-1.10/bin/go command."
    #  exit_script 1 "The Golang 'go' command must be installed in the system PATH. Aborting."
    #fi
    #print_green "Created symlink: /usr/bin/go -> /usr/lib/go-1.10/bin/go"

    # Symlink in /usr/local/bin
    if ! ${sudo_cmd} ln ${ln_args} /usr/lib/go-1.10/bin/go /usr/local/bin/go; then
      print_red "Failed to create /usr/local/bin symlink for /usr/lib/go-1.10/bin/go command."
      exit_script 1 "The Golang 'go' command must be installed in the system PATH. Aborting."
    fi
    print_green "Created symlink: /usr/local/bin/go -> /usr/lib/go-1.10/bin/go"

    if ! hash go 2>/dev/null; then
      print_red "Golang 'go' command is still missing from PATH."
      exit_script 1 "You need to install ${pkg_name}. Aborting."
    fi

    print_green "Found Golang v1.10 binaries; 'go' command is in PATH."
    return
  fi

  return
}

# Attempts to install Ruby v2.20
function install_ruby_v220()
{
  if [ "${INSTALL_MISSING}" != "true" ]; then
    exit_script 1 "You need to install Ruby >= v2.1; aborting..."
  fi

  add_ruby_src
  install_pkg "ruby2.2"
  install_pkg "ruby2.2-dev"

  if ! hash ruby2.2 2>/dev/null; then
    print_red "Ruby v2.20 installation failed: 'ruby2.2' missing from PATH."
    exit_script 1 "You need to install ruby >= v2.1; aborting..."
  fi

  if [ ! -e "/usr/local/bin/ruby" ]; then
    # Check if 'sudo' is required
    sudo_cmd=""
    if [[ $EUID -ne 0 ]]; then
      if ! hash sudo 2>/dev/null; then
        print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package."
        exit_script 1 "You need to install sudo. Aborting."
      else
        sudo_cmd="sudo"
      fi
    fi

    RUBY22_PATH=$(which ruby2.2)
    if [ -L "${RUBY22_PATH}" ]; then
      exit_script 1 "The path '${RUBY22_PATH}' is already a symlink."
    fi

    print_yellow "Creating /usr/local/bin symlink for '${RUBY22_PATH}' command ..."

    # Create a symlink for 'ruby' command.
    ln_args="-s"
    if [ $VERBOSITY -gt 0 ]; then
      ln_args="-v ${ln_args}"
    fi

    # Symlink in /usr/local/bin
    if ! ${sudo_cmd} ln ${ln_args} ${RUBY22_PATH} /usr/local/bin/ruby; then
      print_red "Failed to create /usr/local/bin symlink for ${RUBY22_PATH} command."
      exit_script 1 "The 'ruby' command must be installed in the system PATH. Aborting."
    fi
    print_green "Created symlink: /usr/local/bin/ruby -> ${RUBY22_PATH}"

    if ! hash ruby 2>/dev/null; then
      print_red "The 'ruby' command is still missing from PATH."
      exit_script 1 "You need to install Ruby >= 2.1. Aborting."
    fi

    print_green "Found Ruby binaries; 'ruby' command is in PATH."
    return
  fi

  return
}

function check_installed()
{
  pkg_name="$1"

  if [ -z "${pkg_name}" ]; then
    exit_script 1 "Package name not provided to check script."
  fi

  if hash apt-cache 2>/dev/null; then
    if [ ! -z "$(apt-cache policy ${pkg_name} | grep -v '(none)' | grep Installed)" ]; then
      return 0
    fi
  fi

  return 1
}

function install_gem()
{
  gem_name="$1"

  if [ -z "${gem_name}" ]; then
    exit_script 1 "No gem name provided to install function."
  fi

  if [ ! -z "$(gem list | grep ${gem_name})" ]; then
    #print_green "Required Ruby gem '${gem_name}' is already installed."
    return 0
  fi

  if ! check_installed "ruby"; then
    exit_script 1 "The 'ruby' package is not installed; cannot install gem. Aborting..."
  fi

  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing gem."
      exit_script 1 "You need to install the Ruby gem '${gem_name}'. Aborting."
    else
      sudo_cmd="sudo"
    fi
  fi

  if [ "${INSTALL_MISSING}" == "true" ]; then
    if hash gem 2>/dev/null; then
      gem_args=""
      if [ $VERBOSITY -gt 0 ]; then
        gem_args="--verbose $gem_args"
      fi
      print_yellow "Installing Ruby gem '${gem_name}' ..."
      if ! ${sudo_cmd} gem install ${gem_args} ${gem_name}; then
        exit_script 1 "Failed to install Ruby gem '${gem_name}'."
      fi
      return 0
    fi
  fi

  exit_script 1 "You need to install Ruby gem '${gem_name}'. Aborting."
}

function install_pkg()
{
  pkg_name="$1"

  if [ -z "${pkg_name}" ]; then
    exit_script 1 "Package name not provided to check script."
  fi

  if check_installed "${pkg_name}"; then
    # package is already installed
    if [ $VERBOSITY -gt 0 ]; then
      echo "Package '${pkg_name}' is already installed."
    fi
    return 0
  fi

  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      print_yellow "WARNING: 'sudo' not found in PATH; cannot install missing package."
      exit_script 1 "You need to install sudo. Aborting."
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
      return 0
    fi
  fi

  exit_script 1 "You need to install ${pkg_name}. Aborting."
}

function check_golang_version()
{
  if hash go 2>/dev/null; then
    GO_VERSION=$(go version | head -n1 | grep -Po '(?<=\sgo)[0-9\.]+(?=\s)')
    if version_gt $GO_VERSION $GO_MIN_VERSION; then
      return 0
    fi
  fi
  print_yellow "WARNING: Missing Golang go >= ${GO_MIN_VERSION}; trying to install..."
  # add_golang_src
  install_golang_v110
}

function check_ruby_version()
{
  if hash ruby 2>/dev/null; then
    RUBY_VERSION=$(ruby --version | head -n1 | grep -Po '(?<=\s)([1-9][0-9]{0,8}|0)(\.([1-9][0-9]{0,8}|0)){1,3}')
    if version_gt $RUBY_VERSION $RUBY_MIN_VERSION; then
      return 0
    fi
  fi
  # add ruby 2.20 source and install it
  print_yellow "WARNING: Missing Ruby >= ${RUBY_MIN_VERSION}; trying to install..."
  install_ruby_v220
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
hash add-apt-repository 2>/dev/null || { install_pkg "software-properties-common"; }
hash make 2>/dev/null || { install_pkg "make"; }
hash gcc 2>/dev/null || { install_pkg "gcc"; }
hash gnutls-cli 2>/dev/null || { install_pkg "gnutls-bin"; }
hash clang++ 2>/dev/null || { install_pkg "clang"; }
hash openssl 2>/dev/null || { install_pkg "openssl"; }
hash git 2>/dev/null || { install_pkg "git"; }
hash jq 2>/dev/null || { install_pkg "jq"; }

# Install Golang and Ruby
#install_pkg "ruby-dev";
check_ruby_version
check_golang_version

# Install required libraries
install_pkg "libnspr4-dev"
install_pkg "libcurl4-openssl-dev"
install_pkg "libnss3-dev"
install_pkg "libnss3-tools"
install_pkg "libssl-dev"

# Install Ruby gems
install_gem "simpleidn"
install_gem "public_suffix"

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
