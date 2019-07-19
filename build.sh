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

GO_MIN_VERSION=1.11
RUBY_MIN_VERSION=2.2

VERBOSITY=0
ETCKEEPER_COMMIT="true"
INSTALL_MISSING="true"
NO_COLOR="false"
BOLD_TAGGED="true"
PKG_UPDATED="false"

function is_number()
{
  if [ -z "${1}" ]; then
    return 1
  fi

  re='^[0-9]+$'
  if [[ ${1} =~ $re ]]; then
    return 0
  fi

  return 1
}

function print_ex()
{
  st=0
  fg=39
  bg=49
  str="${1}"

  if [ "${NO_COLOR}" == "false" ]; then

  if [ -n "${2}" ]; then
    if ! is_number "${2}"; then
      exit_script 1 "Invalid argument passed to function: '${2}' is not a valid number."
    fi
    st="${2}"
  fi
  if [ -n "${3}" ]; then
    if ! is_number "${3}"; then
      exit_script 1 "Invalid argument passed to function: '${3}' is not a valid number."
    fi
    fg="${3}"
  fi
  if [ -n "${4}" ]; then
    if ! is_number "${4}"; then
      exit_script 1 "Invalid argument passed to function: '${4}' is not a valid number."
    fi
    bg="${4}"
  fi

  echo -e "\e[0m\e[${st};${bg};${fg}m${str}\e[0m"
  else
  echo "${1}"
  fi
}

function print_ex_tagged()
{
  st=0
  fg=39
  bg=49
  hdr="${1}"
  str="${2}"

  if [ -z "${hdr}" ]; then
    hdr="INFO"
  fi

  if [ "${NO_COLOR}" == "false" ]; then

  if [ -n "${3}" ]; then
    if ! is_number "${3}"; then
      exit_script 1 "ERROR: Invalid argument passed to function: '${3}' is not a valid number."
    fi
    st="${3}"
  fi
  if [ -n "${4}" ]; then
    if ! is_number "${4}"; then
      exit_script 1 "Invalid argument passed to function: '${4}' is not a valid number."
    fi
    fg="${4}"
  fi
  if [ -n "${5}" ]; then
    if ! is_number "${5}"; then
      exit_script "Invalid argument passed to function: '${5}' is not a valid number."
    fi
    bg="${5}"
  fi

  echo -e "\e[0m\e[1;${bg};${fg}m${1}:\e[0m\e[${st};${bg};${fg}m ${str}\e[0m"
  else
  echo "${1}: ${2}"
  fi
}

function print_normal()
{
  fg=39
  bg=49
  str="${1}"

  if [ -n "${2}" ]; then
    fg="${2}"
  fi
  if [ -n "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 0 "${fg}" "${bg}"
}

function print_bold()
{
  fg=39
  bg=49
  str="${1}"

  if [ -n "${2}" ]; then
    fg="${2}"
  fi
  if [ -n "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 1 "${fg}" "${bg}"
}

function print_ul()
{
  fg=39
  bg=49
  str="${1}"

  if [ -n "${2}" ]; then
    fg="${2}"
  fi
  if [ -n "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 4 "${fg}" "${bg}"
}

function print_tagged()
{
  fg=39
  bg=49
  tag="${1}"
  str="${2}"

  if [ -n "${3}" ]; then
    fg="${3}"
  fi
  if [ -n "${4}" ]; then
    bg="${4}"
  fi

  if [ "${BOLD_TAGGED}" == "true" ]; then
    print_ex_tagged "${tag}" "${str}" 0 "${fg}" "${bg}"
  else
    print_ex "${tag}: ${str}" 0 "${fg}" "${bg}"
  fi
}

function print_info()
{
  print_tagged "INFO" "${1}" 33
  #print_tagged "INFO" "${1}"
}

function print_error()
{
  print_tagged "ERROR" "${1}" 31
}

function print_pass()
{
  print_tagged "OK" "${1}" 32
}

function print_warn()
{
  print_tagged "WARNING" "${1}" 33
}

function print_header()
{
  print_ul "${1}"
  #print_bold "${1}" 34
}

function print_green()
{
  print_ex "${1}" 0 32
}

function print_red()
{
  print_ex "${1}" 0 31
}

function print_yellow()
{
  print_ex "${1}" 0 33
}

function exit_script()
{
  # Default exit code is 1
  local exit_code=1

  re='^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
  if echo "$1" | grep -q -E "$re"; then
    exit_code=$1
    shift
  fi

  re='[[:alnum:]]'
  if echo "$*" | grep -iq -E "$re"; then
    if [ "$exit_code" -eq 0 ]; then
      print_info  "$*"
    else
      print_error "$*" 1>&2
    fi
  fi

  # Print 'aborting' string if exit code is not 0
  [ "$exit_code" -ne 0 ] && echo >&2 "Aborting script..."

  exit "$exit_code"
}

function usage()
{
    # Prints out usage and exit.
    sed -e "s/^    //" -e "s|SCRIPT_NAME|$(basename "$0")|" << "EOF"
    USAGE

    Install required packages and build all third-party certificate linters
    used by the 'lint.sh' wrapper.

    SYNTAX
            SCRIPT_NAME [OPTIONS]

    OPTIONS

     -c, --clean             Clean all downloaded and compiled objects.
     -r, --reset             Reset all third-party modules.
     -i, --install-missing   Only install missing packages (do not build).
     -u, --update            Only update Git modules (do not build).
     -t, --test              Run automated source code quality tests.

     --no-install-missing    Do not install missing packages.
     --no-etckeeper          Do not auto-commit /etc changes under VCS.

     -v, --verbose           Make the script more verbose.
     -h, --help              Prints this usage.

EOF

    exit_script "$@"
}

function test_arg()
{
  # Used to validate user input
  local arg="$1"
  local argv="$2"

  if [ -z "$argv" ]; then
    if echo "$arg" | grep -q -E '^-'; then
      usage "Null argument supplied for option $arg"
    fi
  fi

  if echo "$argv" | grep -q -E '^-'; then
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
  echo "${dir}"
  return
}

function version_gt() { test "$(printf '%s\n' "$@" | sort -bt. -k1,1 -k2,2n -k3,3n -k4,4n -k5,5n | head -n 1)" != "$1"; }

function check_etckeeper()
{
  if [[ $EUID -ne 0 ]]; then
    print_warn "Skipping etckeeper check (must run as root to commit /etc changes)..."
    return
  fi

  # git handling for etckeeper (check if /etc/.git exists)
  if [ -d /etc/.git  ] && hash git 2>/dev/null; then
    if git -C "/etc" rev-parse > /dev/null 2>&1; then
      # check /etc/apt for modifications
      # if there are changes, commit them
      if [[ "$(git --git-dir=/etc/.git --work-tree=/etc status --porcelain -- /etc/apt|grep -E '^(M| M)')" != "" ]]; then
        if [ "${ETCKEEPER_COMMIT}" != "true" ]; then
          print_warn "Uncommitted changes under version control: /etc/apt"
          return
        fi
        print_info "Auto-commit changes to /etc/apt (directory under version control) ..."
        pushd /etc > /dev/null 2>&1 || exit_script 1 "Failed to change directories."
        sudo git add --all /etc/apt
        sudo git commit -v -m "apt: auto-commit configuration changes."
        popd > /dev/null 2>&1 || exit_script 1 "Failed to change directories."
      fi
    fi
  fi
}

# Adds a package source for Ruby
# This may be required if the distribution does not provide a new enough version of Ruby
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
# This may be required if the distribution does not provide a new enough version of Golang
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
    print_warn "Skipping package source configuration for '$ppa_name'."
    return 1
  fi

  if ! hash apt-get 2>/dev/null; then
    print_warn "Missing apt-get command; cannot configure PPA '$ppa_name'."
    return 1
  fi
  if ! hash add-apt-repository 2>/dev/null; then
    print_warn "Missing add-apt-repository command; cannot configure PPA '$ppa_name'."
    return 1
  fi

  for f in /etc/apt/sources.list.d/*; do
    if ! echo "$f" | grep -P '\.save$' > /dev/null 2>&1; then
      if grep -ni "$ppa_name" "$f" | grep -q -v -P '^([\s]+)?\#'; then
        print_pass "Found custom PPA configuration for package source '$ppa_name'."
        return 0
      fi
    fi
  done

  if [ $VERBOSITY -gt 0 ]; then
    print_info "Configuring '$ppa_name' package source for apt-get ..."
  fi

  sudo_cmd=""
  if ! sudo_cmd="$(get_sudo_cmd)"; then
    exit_script 1 "You need to install sudo. Aborting."
  fi

  if ! ${sudo_cmd} add-apt-repository --yes "ppa:${ppa_name}"; then
    exit_script 1 "Failed to configure '$ppa_name' package source for apt command."
  fi
  if ! ${sudo_cmd} apt-get update; then
    exit_script 1 "Failed to update apt cache."
  fi

  print_pass "Added custom package source '$ppa_name' for apt-get."

  check_etckeeper
  return 0
}

# Attempts to install Golang
function install_golang()
{
  if [ "${INSTALL_MISSING}" != "true" ]; then
    exit_script 1 "You need to install golang-go >= v${GO_MIN_VERSION}; aborting..."
  fi

  add_golang_src
  install_pkg "golang-${GO_MIN_VERSION}-go"

  if [ ! -e "/usr/lib/go-${GO_MIN_VERSION}/bin/go" ]; then
    print_error "Golang v${GO_MIN_VERSION} installation failed: missing required file '/usr/lib/go-${GO_MIN_VERSION}/bin/go'."
    exit_script 1 "You need to install golang-go >= v${GO_MIN_VERSION}; aborting..."
  fi

  if [ ! -e "/usr/local/bin/go" ]; then
    print_info "Creating /usr/local/bin symlink for Golang 'go' command ..."

    # Check if 'sudo' is required
    sudo_cmd=""
    if ! sudo_cmd="$(get_sudo_cmd)"; then
      exit_script 1 "You need to install sudo. Aborting."
    fi

    # Create a symlink for 'go' command.
    ln_args="-s -f"
    if [ $VERBOSITY -gt 0 ]; then
      ln_args="-v ${ln_args}"
    fi

    # Symlink in /usr/local/bin
    symlink_cmd="${sudo_cmd} ln ${ln_args}"
    if ! ${symlink_cmd} "/usr/lib/go-${GO_MIN_VERSION}/bin/go" "/usr/local/bin/go"; then
      print_error "Failed to create /usr/local/bin symlink for /usr/lib/go-${GO_MIN_VERSION}/bin/go command."
      exit_script 1 "The Golang 'go' command must be installed in the system PATH. Aborting."
    fi
    print_pass "Created symlink: /usr/local/bin/go -> /usr/lib/go-${GO_MIN_VERSION}/bin/go"

    if ! hash go 2>/dev/null; then
      print_error "Golang 'go' command is still missing from PATH."
      exit_script 1 "You need to install ${pkg_name}. Aborting."
    fi

    print_pass "Found Golang v${GO_MIN_VERSION} binaries; 'go' command is in PATH."
    return
  fi

  return
}

# Attempts to install Ruby
function install_ruby()
{
  if [ "${INSTALL_MISSING}" != "true" ]; then
    exit_script 1 "You need to install Ruby >= v${RUBY_MIN_VERSION}; aborting..."
  fi

  add_ruby_src
  install_pkg "ruby${RUBY_MIN_VERSION}"
  install_pkg "ruby${RUBY_MIN_VERSION}-dev"

  if ! hash ruby${RUBY_MIN_VERSION} 2>/dev/null; then
    print_error "Ruby v${RUBY_MIN_VERSION} installation failed: 'ruby${RUBY_MIN_VERSION}' missing from PATH."
    exit_script 1 "You need to install ruby >= v${RUBY_MIN_VERSION}; aborting..."
  fi

  if [ ! -e "/usr/local/bin/ruby" ]; then
    RUBY_PATH=$(command -v ruby${RUBY_MIN_VERSION})
    if [ -L "${RUBY_PATH}" ]; then
      exit_script 1 "The path '${RUBY_PATH}' is already a symlink."
    fi

    print_info "Creating /usr/local/bin symlink for '${RUBY_PATH}' command ..."

    # Check if 'sudo' is required
    sudo_cmd=""
    if ! sudo_cmd="$(get_sudo_cmd)"; then
      print_warn "Cannot install Ruby package."
      exit_script 1 "You need to install sudo. Aborting."
    fi

    # Create a symlink for 'ruby' command.
    ln_args="-s -f"
    if [ $VERBOSITY -gt 0 ]; then
      ln_args="-v ${ln_args}"
    fi

    # Symlink in /usr/local/bin
    symlink_cmd="${sudo_cmd} ln ${ln_args}"
    if ! ${symlink_cmd} "${RUBY_PATH}" "/usr/local/bin/ruby"; then
      print_error "Failed to create /usr/local/bin symlink for ${RUBY_PATH} command."
      exit_script 1 "The 'ruby' command must be installed in the system PATH. Aborting."
    fi
    print_pass "Created symlink: /usr/local/bin/ruby -> ${RUBY_PATH}"

    if ! hash ruby 2>/dev/null; then
      print_error "The 'ruby' command is still missing from PATH."
      exit_script 1 "You need to install Ruby >= ${RUBY_MIN_VERSION}. Aborting."
    fi

    print_pass "Found Ruby binaries; 'ruby' command is in PATH."
    return
  fi

  return
}

# request the sudo command
function get_sudo_cmd()
{
  sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    if ! hash sudo 2>/dev/null; then
      return 1
      # exit_script 1 "You need to install sudo. Aborting."
    fi

    print_info >&2 "Requesting root permissions via sudo invocation..."
    sudo_cmd="sudo"
  fi

  echo "${sudo_cmd}"
  return 0
}

function check_installed()
{
  pkg_name="$1"

  if [ -z "${pkg_name}" ]; then
    exit_script 1 "Package name not provided to check script."
  fi

  if hash apt-cache 2>/dev/null; then
    if apt-cache policy "${pkg_name}" | grep -v '(none)' | grep -q Installed; then
      return 0
    fi
  fi

  return 1
}

function install_pkg()
{
  if [ "${INSTALL_MISSING}" != "true" ]; then
    print_warn "Skipping package installation for '${pkg_name}'."
    return 1
  fi

  pkg_name="$1"
  if [ -z "${pkg_name}" ]; then
    exit_script 1 "Package name not provided to check script."
  fi

  if check_installed "${pkg_name}"; then
    # package is already installed
    #if [ $VERBOSITY -gt 0 ]; then
    print_pass "Package '${pkg_name}' is installed."
    #fi
    return 0
  fi

  # Check if 'sudo' is required
  sudo_cmd=""
  if ! sudo_cmd="$(get_sudo_cmd)"; then
    exit_script 1 "You need to install sudo. Aborting."
  fi

  if hash apt-get 2>/dev/null; then
    if [ "${PKG_UPDATED}" != "true" ]; then
      print_info "Updating apt cache..."
      if ! ${sudo_cmd} apt-get update; then
        exit_script 1 "Failed to update apt cache."
      fi
      PKG_UPDATED="true"
    fi

    print_info "Installing missing package '${pkg_name}' via apt-get ..."
    if ! ${sudo_cmd} apt-get install -V -y "${pkg_name}"; then
      exit_script 1 "Failed to install package '${pkg_name}'."
    fi
    return 0
  fi

  exit_script 1 "You need to install ${pkg_name}. Aborting."
}

function is_source_repo_enabled()
{
  source="$1"
  if [ -z "$source" ]; then
    exit_script 1 "Missing source argument to function."
  fi

  if hash apt-cache 2>/dev/null; then
    if ! hash lsb_release 2>/dev/null; then
      exit_script 1 "Unable to determine OS release (missing lsb_release command)."
    fi

    os_info="$(lsb_release --short --id --release --codename)"
    { read -r os_id; read -r os_release; read -r os_codename; } <<< "$os_info"

    if apt-cache policy | grep -q -E "^(\s+)?release\sv=$os_release,o=${os_id},a=$os_codename,n=$os_codename,l=${os_id},c=${source}"; then
      print_pass "Package source '${source}' is already enabled."
      return 0
    fi

    if ! sudo_cmd="$(get_sudo_cmd)"; then
      print_error "Cannot install missing source '${source}'."
      exit_script 1 "You need to install sudo. Aborting."
    fi

    if ${sudo_cmd} add-apt-repository --yes "${source}"; then
      print_pass "Enabled package source '${source}'."
      return 0
    else
      exit_script 1 "Failed to enable package source '${source}'."
    fi
  fi

  exit_script 1 "The current operating system lacks a supported package manager."
}

# Configure the system package manager to support subsequent use.
# Currently only APT manager is supported.
function configure_pkg_manager()
{
  if [ "${INSTALL_MISSING}" != "true" ]; then
    print_warn "Skipping package manager configuration."
    return 0
  fi

  if hash apt-get 2>/dev/null; then
    # Make sure required tooling is installed
    install_pkg "software-properties-common"

    # Enable the 'universe' package source.
    if ! is_source_repo_enabled "universe"; then
      # Check if 'sudo' is required
      sudo_cmd=""
      if ! sudo_cmd="$(get_sudo_cmd)"; then
        print_warn    "Cannot configure package manager."
        exit_script 1 "You need to install sudo. Aborting."
      fi

      if ! ${sudo_cmd} add-apt-repository --yes universe; then
        exit_script 1 "Failed to enable 'universe' package repository."
      fi
      print_pass "Enabled APT repository 'universe'."
      return 0
    fi
  fi

  return 0
}

function install_gem()
{
  gem_name="$1"

  if [ -z "${gem_name}" ]; then
    exit_script 1 "No gem name provided to install function."
  fi

  if [ "${INSTALL_MISSING}" != "true" ]; then
    print_warn "Skipping Gem installation for '${gem_name}'."
    return 0
  fi

  if gem list | grep -q "${gem_name}"; then
    print_pass "Required Ruby gem '${gem_name}' is already installed."
    return 0
  fi

  if ! check_installed "ruby"; then
    exit_script 1 "The 'ruby' package is not installed; cannot install gem. Aborting..."
  fi

  # Check if 'sudo' is required
  sudo_cmd=""
  if ! sudo_cmd="$(get_sudo_cmd)"; then
    print_warn    "Cannot install Ruby gem '${gem_name}'"
    exit_script 1 "You need to install sudo. Aborting."
  fi

  if hash gem 2>/dev/null; then
    gem_args=""
    if [ $VERBOSITY -gt 0 ]; then
      gem_args="--verbose $gem_args"
    fi
    print_info "Installing Ruby gem '${gem_name}' ..."
    gem_cmd="${sudo_cmd} gem install ${gem_args}"
    if ! ${gem_cmd} "${gem_name}"; then
      exit_script 1 "Failed to install Ruby gem '${gem_name}'."
    fi
    return 0
  fi

  exit_script 1 "You need to install Ruby gem '${gem_name}'. Aborting."
}

function check_golang_version()
{
  if hash go 2>/dev/null; then
    GO_VERSION_FULL=$(go version | head -n1 | grep -Po '(?<=\sgo)[0-9\.]+(?=\s)')
    GO_VERSION=$(go version | head -n1 | grep -Po '(?<=\sgo)[0-9]+\.[0-9]+(?=(\s|\.))')
    if version_gt "$GO_VERSION_FULL" "$GO_MIN_VERSION"; then
      if [ -e "/usr/lib/go-${GO_VERSION}" ]; then
        return 0
      else
        print_warn "Found Go v${GO_VERSION_FULL} in PATH but missing GOROOT: /usr/lib/go-${GO_VERSION}"
      fi
    fi
  fi
  print_warn "Missing Golang go >= ${GO_MIN_VERSION}; trying to install..."
  install_golang
}

function check_ruby_version()
{
  # always install base ruby-dev package
  install_pkg "ruby-dev"

  if hash ruby 2>/dev/null; then
    RUBY_VERSION=$(ruby --version | head -n1 | grep -Po '(?<=\s)([1-9][0-9]{0,8}|0)(\.([1-9][0-9]{0,8}|0)){1,3}')
    if version_gt "$RUBY_VERSION" "$RUBY_MIN_VERSION"; then
      return 0
    fi
  fi
  # add ruby source and install it
  print_warn "Missing Ruby >= ${RUBY_MIN_VERSION}; trying to install..."
  install_ruby
}

MAKE_ARG="all"
CLEAN_MODE="false"
RESET_MODE="false"
INSTALL_MODE="false"
UPDATE_MODE="false"
TEST_MODE="false"

# process arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--clean)
      CLEAN_MODE="true"
      MAKE_ARG="clean"
      shift
    ;;
    -r|--reset)
      RESET_MODE="true"
      CLEAN_MODE="true"
      MAKE_ARG="clean"
      shift
    ;;
    --no-install-missing)
      INSTALL_MISSING="false"
      shift
    ;;
    -i|--install-missing)
      INSTALL_MODE="true"
      shift
    ;;
    -t|--test)
      TEST_MODE="true"
      shift
    ;;
    -u|--update)
      UPDATE_MODE="true"
      shift
    ;;
    --no-etckeeper)
      ETCKEEPER_COMMIT="false"
      shift
    ;;
    -h|--help)
      usage
    ;;
    -v|--verbose)
      ((VERBOSITY++))
      shift
    ;;
    -vv)
      ((VERBOSITY++))
      ((VERBOSITY++))
      shift
    ;;
    -vvv)
      ((VERBOSITY++))
      ((VERBOSITY++))
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

if [ "${CLEAN_MODE}" != "true" ] && [ "${UPDATE_MODE}" != "true" ]; then

print_info "Checking required packages..."

if ! configure_pkg_manager; then
  exit_script 1 "Failed to configure package manager."
fi

# Check for missing packages
hash make 2>/dev/null || { install_pkg "make"; }
hash gcc 2>/dev/null || { install_pkg "gcc"; }
hash gnutls-cli 2>/dev/null || { install_pkg "gnutls-bin"; }
hash clang++ 2>/dev/null || { install_pkg "clang"; }
hash openssl 2>/dev/null || { install_pkg "openssl"; }
hash git 2>/dev/null || { install_pkg "git"; }
hash jq 2>/dev/null || { install_pkg "jq"; }

# Check for missing source code lint tools
hash shellcheck 2>/dev/null || { install_pkg "shellcheck"; }

# Install Golang and Ruby
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

fi

if [ "${CLEAN_MODE}" != "true" ] && [ "${RESET_MODE}" != "true" ]; then

# Update sub-modules
print_info "Initializing Git submodules..."
if ! git submodule init; then
  exit_script 1 "Failed to initialize required modules."
fi
print_info "Updating Git submodules..."
if ! git submodule update --recursive; then
  exit_script 1 "Failed to update required modules."
fi

fi

if [ "${INSTALL_MODE}" != "true" ] && [ "${UPDATE_MODE}" != "true" ]; then

if ! { [ "${RESET_MODE}" == "true" ] && [ "${CLEAN_MODE}" != "false" ]; }; then

# Build all modules
result=0
if [ "${CLEAN_MODE}" != "true" ]; then
print_info "Compiling sources..."
else
print_info "Cleaning sources..."
fi
MAKE_CMD="make ${MAKE_ARG}"
if ! ${MAKE_CMD}; then
  result=1
fi

fi

if [ "${RESET_MODE}" == "true" ]; then
  # De-initialize submodules
  print_info "De-inintializing Git submodules..."
  if ! git submodule deinit --force .; then
    result=1
    print_error "Failed to de-initialize Git submodules."
  fi

  # The sequence below will perform a hard-reset, including all sub-modules
  #if ! git clean -xfd; then
  #  result=1
  #  print_error "Git cleanup failed."
  #fi
  if ! git submodule foreach --recursive git clean -xfd; then
    result=1
    print_error "Git submodule cleanup failed."
  fi
  #if ! git reset --hard; then
  #  result=1
  #  print_error "Failed to perform Git hard reset."
  #fi
  if ! git submodule foreach --recursive git reset --hard; then
    result=1
    print_error "Failed to reset all Git submodules."
  fi
  if ! git submodule update --init --remote --recursive; then
    result=1
    print_error "Git submodule initialization failed."
  fi
fi

if [[ ${result} -ne 0 ]]; then
  if [ "${CLEAN_MODE}" != "true" ]; then
  print_error "Problems encountered during build; failed to compile all linting modules."
  else
  print_error "Failed to clean all linting module sources."
  fi
else
  if [ "${CLEAN_MODE}" != "true" ]; then
  print_pass  "Finished compiling all linting modules."
  else
  print_pass  "All module sources cleaned without error."
  fi
fi

if [ "${TEST_MODE}" == "true" ]; then
  print_info "Running source code tests...."
  check_result=0
  if ! make check; then
    check_result=1
  elif ! make test; then
    check_result=1
  fi
  if [ ${check_result} -ne 0 ]; then
    print_error  "Source code test failed."
  else
    print_pass   "Source code tests passed."
  fi
fi

fi

exit_script ${result}
