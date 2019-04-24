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
# A simple Bash wrapper for a collection of x509 certificate
# and Public-key Infrastructure (PKI) checks.
#
# The script enables quick and easy identification of potential
# issues with generated x509 certificates.
#
## USAGE
#
# To initialize Git sub-modules and compile all certificate lints,
# run the 'build.sh' script found in the root directory:
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

# Script variables
VERBOSITY=0
ERROR_LEVEL=0
DEBUG_LEVEL=0
SECURITY_LEVEL=0
SILENT="false"
NO_COLOR="true"
BOLD_TAGGED="false"
NSS_VERIFY_CHAIN="false"
OPENSSL_ARGS="-verbose -x509_strict -policy_print -policy_check"

CERTTOOL_MIN_VER="3.0.0"
RUBY_MIN_VERSION="2.2"

OPENSSL_MIN_VERSION_NUM="1.1.0"
OPENSSL_MIN_VERSION_EXT="g"

GOLANG_INSTALLED=0
if hash go 2>/dev/null; then
  GOLANG_INSTALLED=1
fi

# define script error messages
errorMessages=([0]="Certificate passed all checks."
               [1]="Certificate linting produced one or more warnings; manual validation required."
               [2]="Certificate linting found one or more critical issues.")

# define supported security levels
# level 0: 112 bits (RSA >= 2048  bits ; ECC >= 224 bits)
# level 1: 128 bits (RSA >= 3072  bits ; ECC >= 256 bits)
# level 2: 192 bits (RSA >= 7680  bits ; ECC >= 384 bits)
# level 3: 256 bits (RSA >= 15360 bits ; ECC >= 512 bits)
securityLevels=([0]="minimum" [1]="medium" [2]="high" [3]="extreme")

# define table of EKU purpose arguments for various tools
certPurposes=(  [0]="client"    [1]="server"    [2]="mailsign"  [3]="mailencrypt"  [4]="ocsp" [5]="anyCA" )
opensslk_opts=( [0]="sslclient" [1]="sslserver" [2]="smimesign" [3]="smimeencrypt" [4]=""     [5]=""      )
vfychain_opts=( [0]="0"         [1]="1"         [2]="4"         [3]="5"            [4]="10"   [5]="11"    )
certutil_opts=( [0]="C"         [1]="V"         [2]="S"         [3]="R"            [4]="O"    [5]="A"     )
golangku_opts=( [0]="2"         [1]="1"         [2]="4"         [3]="4"            [4]="9"    [5]=""      )
gnutlsku_opts=( [0]="1.3.6.1.5.5.7.3.2"
                [1]="1.3.6.1.5.5.7.3.1"
                [2]="1.3.6.1.5.5.7.3.4"
                [3]="1.3.6.1.5.5.7.3.4"
                [4]="1.3.6.1.5.5.7.3.9"
                [5]="")

# Check for commands which are required to continue executing.
# If one of these is missing the script must exit immediately.
hash grep 2>/dev/null || { echo >&2 "You need to install grep. Aborting."; exit 1; }

# Create an array to track missing packages
declare -a pkg_missing=();
function add_missing_pkg()
{
  if [ -z "$1" ]; then
    usage "Package name cannot be null."
  fi
  if ! echo ${pkg_missing[@]} | grep -q -w "$1"; then
    pkg_name="$1"
    pkg_missing=("${pkg_missing[@]}" "${pkg_name}")
  fi
}

# Check for required comamnds in PATH
hash realpath 2>/dev/null || { add_missing_pkg "realpath"; }
hash openssl 2>/dev/null || { add_missing_pkg "openssl"; }
hash git 2>/dev/null || { add_missing_pkg "git"; }
hash certtool 2>/dev/null || { add_missing_pkg "gnutls-bin"; }
hash jq 2>/dev/null || { add_missing_pkg "jq"; }
hash vfychain 2>/dev/null || { add_missing_pkg "libnss3-tools"; }

# Ruby can be required here; otherwise it will only affect AWS linting
#hash ruby 2>/dev/null || { add_missing_pkg "ruby"; }

if [ ${#pkg_missing[@]} -gt 0 ]; then
  echo >&2 "ERROR: You need to install the following packages: ${pkg_missing[*]}"
  exit 1
fi

# Define additional variables
CERT=""
CA_CERT="false"
X509_MODE=""
CA_CHAIN=""
EV_POLICY=""
EV_HOST=""
PRINT_MODE=""
OPT_PURPOSE=""
OPT_LEVEL=""
OPT_ERROR_LEVEL=0
OPENSSL_SECLVL=2
RUBY_VERSION=""
EV_DETECTED="false"
NO_EV_CHECK="false"

# usage: version_gt( current_version, required_version )
function version_gt() { test "$(printf '%s\n' "$@" | sort -bt. -k1,1 -k2,2n -k3,3n -k4,4n -k5,5n | head -n 1)" != "$1"; }

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

function check_ruby_version()
{
  if hash ruby 2>/dev/null; then
    RUBY_VERSION=$(ruby --version | head -n1 | grep -Po '(?<=\s)([1-9][0-9]{0,8}|0)(\.([1-9][0-9]{0,8}|0)){1,3}')
    if version_gt "$RUBY_VERSION" "$RUBY_MIN_VERSION"; then
      return 0
    fi
  fi
  return 1
}

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

function print_newline()
{
  if [ "${SILENT}" != "true" ]; then
    echo
  fi
}

# Print text with optional color
#   red=31
#   green=32
#   yellow=33
#   blue=34
#   magenta=35
#   cyan=36
function print_ex()
{
  if [ "${SILENT}" == "true" ]; then
    return
  fi
  if [ -z "$1" ]; then
    echo
    return
  fi

  st=0
  fg=39
  bg=49
  str="${1}"

  if [ "${NO_COLOR}" == "false" ]; then

  if [ ! -z "${2}" ]; then
    if ! echo "${2}" | grep -qPo '^[0-9\;]+$'; then
      exit_script 1 "Invalid argument passed to function: '${2}' is not a valid number."
    fi
    st="${2}"
  fi
  if [ ! -z "${3}" ]; then
    if ! is_number "${3}"; then
      exit_script 1 "Invalid argument passed to function: '${3}' is not a valid number."
    fi
    fg="${3}"
  fi
  if [ ! -z "${4}" ]; then
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
  if [ "${SILENT}" == "true" ]; then
    return
  fi
  if [ -z "$1" ]; then
    echo
    return
  fi

  st=0
  fg=39
  bg=49
  hdr="${1}"
  str="${2}"

  if [ -z "${hdr}" ]; then
    hdr="INFO"
  fi

  if [ "${NO_COLOR}" == "false" ]; then

  if [ ! -z "${3}" ]; then
    if ! echo "${3}" | grep -qPo '^[0-9\;]+$'; then
      exit_script 1 "Invalid argument passed to function: '${3}' is not a valid number."
    fi
    st="${3}"
  fi
  if [ ! -z "${4}" ]; then
    if ! is_number "${4}"; then
      exit_script 1 "Invalid argument passed to function: '${4}' is not a valid number."
    fi
    fg="${4}"
  fi
  if [ ! -z "${5}" ]; then
    if ! is_number "${5}"; then
      exit_script 1 "Invalid argument passed to function: '${5}' is not a valid number."
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

  if [ ! -z "${2}" ]; then
    fg="${2}"
  fi
  if [ ! -z "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 0 ${fg} ${bg}
}

function print_bold_ul()
{
  fg=39
  bg=49
  str="${1}"

  if [ ! -z "${2}" ]; then
    fg="${2}"
  fi
  if [ ! -z "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" "1;4" ${fg} ${bg}
}

function print_bold()
{
  fg=39
  bg=49
  str="${1}"

  if [ ! -z "${2}" ]; then
    fg="${2}"
  fi
  if [ ! -z "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 1 ${fg} ${bg}
}

function print_ul()
{
  fg=39
  bg=49
  str="${1}"

  if [ ! -z "${2}" ]; then
    fg="${2}"
  fi
  if [ ! -z "${3}" ]; then
    bg="${3}"
  fi

  print_ex "${str}" 4 ${fg} ${bg}
}

function print_tagged()
{
  fg=39
  bg=49
  tag="${1}"
  str="${2}"

  if [ ! -z "${3}" ]; then
    fg="${3}"
  fi
  if [ ! -z "${4}" ]; then
    bg="${4}"
  fi

  if [ "${BOLD_TAGGED}" == "true" ]; then
    print_ex_tagged "${tag}" "${str}" 0 ${fg} ${bg}
  else
    print_ex "${tag}: ${str}" 0 ${fg} ${bg}
  fi
}

function print_info()
{
  print_tagged "INFO" "${1}"
}

function print_error()
{
  print_tagged "ERROR" "${1}" 31
}

function print_pass()
{
  print_tagged "PASS" "${1}" 32
}

function print_notice()
{
  print_tagged "NOTICE" "${1}"
  #print_tagged "NOTICE" "${1}" 32
}

function print_warn()
{
  print_tagged "WARNING" "${1}" 33
}

function print_debug()
{
  if [ $VERBOSITY -gt 1 ]; then
  print_tagged "DEBUG" "${1}" 36 >&2
  fi
}

function print_data()
{
  print_cyan "${1}"
}

function print_header()
{
  print_bold_ul "${1}"
  #print_ul "${1}"
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

function print_blue()
{
  print_ex "${1}" 0 34
}

function print_magenta()
{
  print_ex "${1}" 0 35
}

function print_cyan()
{
  print_ex "${1}" 0 36
}

function print_yellow()
{
  print_ex "${1}" 0 33
}

function exit_script()
{
  # Default exit code is 1
  local exit_code=1
  local re var

  re='^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
  if echo "$1" | grep -q -E "$re"; then
    exit_code=$1
    shift
  fi

  re='[[:alnum:]]'
  if echo "$*" | grep -iq -E "$re"; then
    if [ $exit_code -eq 0 ]; then
      print_normal  "INFO: $*"  >&2
    else
      print_red     "ERROR: $*" 1>&2
    fi
  fi

  # Print 'aborting' string if exit code is not 0
  [ $exit_code -ne 0 ] && echo >&2 "Aborting script..."

  exit $exit_code
}

function usage()
{
    # Prints out usage and exit.
    sed -e "s/^    //" -e "s|SCRIPT_NAME|$(basename $0)|" << EOF
    USAGE

    Performs various linting tests against the specified X.509 certificate.

    SYNTAX
            SCRIPT_NAME [OPTIONS] ARGUMENTS

    ARGUMENTS

     certificate               The certificate (in PEM format) to lint.

    OPTIONS

     -r, --root                Certificate is a root CA.
     -i, --intermediate        Certificate is an Intermediate CA.
     -s, --subscriber          Certificate is for an end-entity.

     -c, --chain <file>        Specifies a CA chain file to use.
     -o, --policy <oid>        Specifies an OID of a policy to test.
     -n, --hostname <name>     Specifies the hostname for validation.

     -u, --usage <purpose>     Specifies the certificate purpose to test for.
                               Supported options are:
                               - 0=client
                               - 1=server
                               - 2=mailsign
                               - 3=mailencrypt
                               - 4=ocsp
                               - 5=anyCA

     -l, --level <level>       Specify the required certificate security level.
                               Supported options are:
                               - 0=minimum (>= 112 bits) (default)
                               - 1=medium  (>= 128 bits)
                               - 2=high    (>= 192 bits)
                               - 3=extreme (>= 256 bits)

     -e, --error-level <int>   Specify the maximum allowed error level.

     --no-ev-check             Do not validate Extended Validation (EV) certificates.

     -p, --print               Print the input certificate.
     -b, --colors              Print colorful output.
     -q, --quiet               Do not print results to console.
     -v, --verbose             Make the script more verbose.
     -h, --help                Prints this usage.

EOF

    exit_script $@
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

function test_number_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  if ! is_number $argv; then
    usage "Value is not a valid number: '$argv'."
  fi
}

function test_file_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  if ! [ -e "$argv" ]; then
    usage "File does not exist: '$argv'."
  fi
  if [ ! -s "$argv" ]; then
    usage "File is empty: '$argv'."
  fi
}

function test_oid_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  if ! echo $argv | grep -qPo '^([1-9][0-9]{0,8}|0)(\.([1-9][0-9]{0,8}|0)){5,16}$'; then
    usage "Argument is not a valid object identifier: '$argv'"
  fi
}

function test_host_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  host_regex='^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
  if ! $(echo "$argv" | grep -qPo ${host_regex}); then
    usage "Invalid hostname: '${argv}'"
  fi
}

function test_chain()
{
  if [ ! -z "${CA_CHAIN}" ]; then
    usage "Cannot specify multiple chain files."
  fi
}

function test_ev_host()
{
  if [ ! -z "${EV_HOST}" ]; then
    usage "Cannot specify multiple hostnames."
  fi
}

function test_cert()
{
  if [ ! -z "${CERT}" ]; then
    usage "Cannot specify multiple search terms."
  fi
}

function test_mode()
{
  if [ ! -z "${X509_MODE}" ]; then
    usage "Cannot specify conflicting options."
  fi
}

function test_ev_policy()
{
  if [ ! -z "${EV_POLICY}" ]; then
    usage "Cannot specify multiple EV policies."
  fi
}

declare -a zlint_names=();
function add_zlint_lint()
{
  if [ -z "$1" ]; then
    exit_script 1 "zlint lint name cannot be null."
  fi
  if echo ${alt_names[@]} | grep -q -w "$1"; then
    exit_script 1 "zlint lint name processed twice."
  fi
  lint_name="$1"
  zlint_names=("${zlint_names[@]}" "${lint_name}")
}

function is_pem_format()
{
  local file="$1"
  if [ -z "${file}" ] || [ ! -e "${file}" ]; then
    exit_script 1 "No file passed to function."
  fi
  if ! openssl x509 -inform PEM -in "${file}" -text -noout > /dev/null 2>&1; then
    return 1
  fi
  return 0
}

function get_pem_file()
{
  local file="$1"
  if [ -z "${file}" ] || [ ! -e "${file}" ]; then
    exit_script 1 "Invalid file argument passed to function."
  fi

  # check if file is already in PEM format
  if is_pem_format "${file}"; then
    echo "${file}"
    return 0
  fi

  temp_file="$(mktemp -t $(basename ${file}).XXXXXX).pem"
  if ! openssl crl -inform DER -in "${file}" -outform PEM -out "${temp_file}"; then
    exit_script 1 "Failed to convert file from DER->PEM encoding: '${file}'"
  fi

  if ! mv "${temp_file}" "${file}"; then
    exit_script 1 "Failed to replace file '${file}' with updated encoding."
  fi

  echo "${file}"
  return 0
}

function get_crl_http_from_pem()
{
  local pem_file="$1"
  local crl_url

  if [ -z "${pem_file}" ] || [ ! -e "${pem_file}" ]; then
    exit_script 1 "Invalid file path passed to function."
  fi

  if crl_url=$(openssl x509 -noout -text -in "${pem_file}" | grep -A 4 'X509v3 CRL Distribution Points' | grep -Po '(?<=URI\:)(http)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$'); then
    if [ ! -z "${crl_url}" ]; then
      echo "${crl_url}"
      return 0
    fi
  fi

  return 1
}

function get_purpose()
{
  if [ -z "$1" ]; then
    usage "Purpose cannot be null."
  fi

  temp=$1
  re='^[0-9]+$'
  if [[ $temp =~ $re ]] ; then
    temp="${certPurposes[temp]}"
    if [ -z "${temp}" ]; then
      return 1
      #usage "'$1' is not mapped to a known purpose."
    fi
  fi
  if ! echo ${certPurposes[@]} | grep -q -w "$temp"; then
    return 1
    #usage "'$temp' is not a valid purpose."
  fi

  echo ${temp}
  return 0
}

function get_level()
{
  if [ -z "$1" ]; then
    exit_script 1 "Security level cannot be null."
  fi

  temp=$1
  re='^[0-9]+$'
  if [[ $temp =~ $re ]] ; then
    temp="${securityLevels[temp]}"
    if [ -z "${temp}" ]; then
      usage "'$1' is not mapped to a known security level."
    fi
  fi
  if ! echo ${securityLevels[@]} | grep -q -w "$temp"; then
    usage "'$temp' is not a valid security level."
  fi

  echo ${temp}
}

function get_seclvl()
{
  if [ -z "$1" ]; then
    exit_script 1 "Security level cannot be null."
  fi

  value="$1"
  temp="0"

  for i in "${!securityLevels[@]}"; do
    if [[ "${securityLevels[$i]}" = "${value}" ]]; then
      temp=$i
      break;
    fi
  done

  echo "${temp}"
}

function get_openssl_seclvl()
{
  if [ -z "$1" ]; then
    exit_script 1 "Security level cannot be null."
  fi

  value="$1"
  temp=""

  for i in "${!securityLevels[@]}"; do
    if [[ "${securityLevels[$i]}" = "${value}" ]]; then
      temp=$i
      break;
    fi
  done

  echo "$((${temp}+2))"
}

function get_errlvl()
{
  input="${1}"
  if [ -z "${1}" ]; then
    return 0
  fi

  ret=0
  case "${input}" in
    warn|W|Warning|1)
      ret=1
    ;;
    error|fatal|E|F|B|Error|2)
      ret=2
    ;;
  esac

  return ${ret}
}

function get_print_func()
{
  input="${1}"
  if [ -z "${1}" ]; then
    echo "print_normal"
  fi

  case "${input}" in
    pass|0)
      echo "print_pass"
    ;;
    info|I|Info)
      echo "print_info"
    ;;
    warn|W|Warning|1)
      echo "print_warn"
    ;;
    error|fatal|E|F|B|Error|2)
      echo "print_error"
    ;;
    notice|N)
      echo "print_notice"
    ;;
    *)
      echo "print_normal"
    ;;
  esac
  return 0
}

function get_print_func_raw()
{
  input="${1}"
  if [ -z "${1}" ]; then
    echo "print_normal"
  fi

  case "${input}" in
    pass|0)
      echo "print_green"
    ;;
    info|I|Info)
      echo "print_normal"
    ;;
    warn|W|Warning|1)
      echo "print_yellow"
    ;;
    error|fatal|E|F|B|Error|2)
      echo "print_red"
    ;;
    notice|N)
      echo "print_green"
    ;;
    *)
      echo "print_normal"
    ;;
  esac
  return 0
}

# process arguments
[ $# -gt 0 ] || usage
while [ $# -gt 0 ]; do
  case "$1" in
    -r|--root)
      test_mode
      CA_CERT="true"
      X509_MODE="x509lint-root"
      shift
    ;;
    -i|--intermediate)
      test_mode
      CA_CERT="true"
      X509_MODE="x509lint-int"
      shift
    ;;
    -s|--subscriber)
      test_mode
      X509_MODE="x509lint-sub"
      shift
    ;;
    -c|--chain)
      test_chain
      test_file_arg "$1" "$2"
      shift
      CA_CHAIN="$1"
      shift
    ;;
    -o|--policy)
      test_ev_policy
      test_oid_arg "$1" "$2"
      shift
      EV_POLICY="$1"
      shift
    ;;
    -n|--hostname)
      test_ev_host
      test_host_arg "$1" "$2"
      shift
      EV_HOST="$1"
      shift
    ;;
    -p|--print)
      PRINT_MODE="true"
      shift
    ;;
    -u|--usage)
      if [ ! -z "${OPT_PURPOSE}" ]; then
        usage "Cannot specify multiple purposes."
      fi
      test_arg "$1" "$2"
      shift
      # try to convert argument to purpose
      if ! OPT_PURPOSE=$(get_purpose "$1"); then
        usage "Invalid certificate usage: $1"
      fi
      shift
    ;;
    -l|--level)
      if [ ! -z "${OPT_LEVEL}" ]; then
        usage "Cannot specify multiple security levels."
      fi
      test_arg "$1" "$2"
      shift
      # try to convert argument to security level
      OPT_LEVEL=$(get_level "$1")
      shift
    ;;
    -e|--error-level)
      test_number_arg "$1" "$2"
      shift
      OPT_ERROR_LEVEL=$1
      shift
    ;;
    -b|--colors)
      NO_COLOR="false"
      shift
    ;;
    --no-ev-check)
      NO_EV_CHECK="true"
      shift
    ;;
    -h|--help)
      usage
    ;;
    -q|--quiet)
      SILENT="true"
      shift
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
      if [ ! -z "${CERT}" ]; then
        usage "Cannot specify multiple input certificates."
      fi
      test_cert
      test_file_arg "$1"
      CERT="$1"
      shift
    ;;
  esac
done

# export verbosity as an environment variable
export VERBOSITY=$VERBOSITY

if [ ! -z "${OPT_ERROR_LEVEL}" ]; then
  if ! is_number "${OPT_ERROR_LEVEL}"; then
    exit_script "Invalid error level threshold: '${OPT_ERROR_LEVEL}'."
  fi
  ERROR_LEVEL=${OPT_ERROR_LEVEL}
fi
if [ ! -z "${OPT_LEVEL}" ]; then
  SECURITY_LEVEL="${OPT_LEVEL}"
fi
if [ ! -z "${SECURITY_LEVEL}" ]; then
  SECURITY_LEVEL=$(get_level "${SECURITY_LEVEL}")
  OPENSSL_SECLVL=$(get_openssl_seclvl "${SECURITY_LEVEL}")

  if [ $VERBOSITY -gt 1 ]; then
    print_info "Security level '${SECURITY_LEVEL}' (OpenSSL auth_level ${OPENSSL_SECLVL})"
  fi
fi

# level 0: 112 bits (RSA >= 2048  bits ; ECC >= 224 bits)
# level 1: 128 bits (RSA >= 3072  bits ; ECC >= 256 bits)
# level 2: 192 bits (RSA >= 7680  bits ; ECC >= 384 bits)
# level 3: 256 bits (RSA >= 15360 bits ; ECC >= 512 bits)
RSA_MIN_BITS=2048
ECC_MIN_BITS=224
if [ ! -z "${SECURITY_LEVEL}" ]; then
  case "${SECURITY_LEVEL}" in
    minimum)
      RSA_MIN_BITS=2048
      ECC_MIN_BITS=224
    ;;
    medium)
      RSA_MIN_BITS=3072
      ECC_MIN_BITS=256
    ;;
    high)
      RSA_MIN_BITS=7680
      ECC_MIN_BITS=384
    ;;
    extreme)
      RSA_MIN_BITS=15360
      ECC_MIN_BITS=512
    ;;
    *)
       exit_script 1 "Invalid security level: '${SECURITY_LEVEL}'"
    ;;
  esac
fi

#if [ ! -z "${EV_POLICY}" ] && [ -z "${CA_CHAIN}" ]; then
#  usage "Must supply CA chain for EV policy testing."
#fi
#if [ ! -z "${EV_POLICY}" ] && [ -z "${EV_HOST}" ]; then
#  usage "Must supply hostname for EV policy testing."
#fi

KU_GOLANG=0
KU_OPENSSL=""
KU_VFYCHAIN=""
KU_CERTUTIL=""
KU_GNUTLS=""
if [ -z "${OPT_PURPOSE}" ]; then
  if [ "${CA_CERT}" == "true" ]; then
    OPT_PURPOSE="anyCA"
  fi
fi
if [ ! -z "${OPT_PURPOSE}" ]; then
  case "${OPT_PURPOSE}" in
    client)
      KU_OPENSSL="${opensslk_opts[0]}"
      KU_VFYCHAIN="${vfychain_opts[0]}"
      KU_CERTUTIL="${certutil_opts[0]}"
      KU_GOLANG="${golangku_opts[0]}"
      KU_GNUTLS="${gnutlsku_opts[0]}"
    ;;
    server)
      KU_OPENSSL="${opensslk_opts[1]}"
      KU_VFYCHAIN="${vfychain_opts[1]}"
      KU_CERTUTIL="${certutil_opts[1]}"
      KU_GOLANG="${golangku_opts[1]}"
      KU_GNUTLS="${gnutlsku_opts[1]}"
    ;;
    mailsign)
      KU_OPENSSL="${opensslk_opts[2]}"
      KU_VFYCHAIN="${vfychain_opts[2]}"
      KU_CERTUTIL="${certutil_opts[2]}"
      KU_GOLANG="${golangku_opts[2]}"
      KU_GNUTLS="${gnutlsku_opts[2]}"
    ;;
    mailencrypt)
      KU_OPENSSL="${opensslk_opts[3]}"
      KU_VFYCHAIN="${vfychain_opts[3]}"
      KU_CERTUTIL="${certutil_opts[3]}"
      KU_GOLANG="${golangku_opts[3]}"
      KU_GNUTLS="${gnutlsku_opts[3]}"
    ;;
    ocsp)
      KU_OPENSSL="${opensslk_opts[4]}"
      KU_VFYCHAIN="${vfychain_opts[4]}"
      KU_CERTUTIL="${certutil_opts[4]}"
      KU_GOLANG="${golangku_opts[4]}"
      KU_GNUTLS="${gnutlsku_opts[4]}"
    ;;
    anyCA)
      KU_OPENSSL="${opensslk_opts[5]}"
      KU_VFYCHAIN="${vfychain_opts[5]}"
      KU_CERTUTIL="${certutil_opts[5]}"
      KU_GOLANG="${golangku_opts[5]}"
      KU_GNUTLS="${gnutlsku_opts[5]}"
    ;;
    *)
      usage "Unsupported certificate purpose '${OPT_PURPOSE}'."
    ;;
  esac
fi

if [ -z "${X509_MODE}" ]; then
  usage "Must specify certificate type."
fi

if [ -z "${CERT}" ]; then
  usage "Must supply a certificate to check."
fi
if [ ! -e "${CERT}" ]; then
  usage "The specified certificate file does not exist."
fi

if ! openssl x509 -text -noout -in "${CERT}" > /dev/null 2>&1; then
  usage "The specified file is not a valid certificate."
fi

VERBOSE_FLAG=""
if [ "${SILENT}" != "true" ] && [ $VERBOSITY -gt 1 ]; then
  VERBOSE_FLAG="-v"
fi

# Get the root directory
DIR=$(get_root_dir)

X509_BIN="${DIR}/lints/x509lint/${X509_MODE}"
ZLINT_BIN="${DIR}/lints/bin/zlint"
AWS_CLINT_DIR="${DIR}/lints/aws-certlint"
GS_CLINT_DIR="${DIR}/lints/gs-certlint"
EV_CHECK_BIN="${DIR}/lints/ev-checker/ev-checker"
GOLANG_LINTS="${DIR}/lints/golang/*.go"

if [ ! -e "${X509_BIN}" ]; then
  usage "Missing required binary (did you build it?): ${X509_BIN}"
fi
if [ ! -e "${EV_CHECK_BIN}" ]; then
  usage "Missing required binary (did you build it?): ${EV_CHECK_BIN}"
fi
if [ ! -e "${AWS_CLINT_DIR}/bin/certlint" ]; then
  usage "Missing required binary (did you build it?): ${AWS_CLINT_DIR}/bin/certlint"
fi
if [ ! -e "${AWS_CLINT_DIR}/bin/cablint" ]; then
  usage "Missing required binary (did you build it?): ${AWS_CLINT_DIR}/bin/cablint"
fi
if [ ! -e "${ZLINT_BIN}" ]; then
  usage "Missing required binary (did you build it?): ${ZLINT_BIN}"
fi

if [ $VERBOSITY -gt 1 ]; then
print_info >&2 "Found  : x509lint   : ${X509_BIN}"
print_info >&2 "Found  : cablint    : ${AWS_CLINT_DIR}/bin/cablint"
print_info >&2 "Found  : certlint   : ${GS_CLINT_DIR}"
print_info >&2 "Found  : zlint      : ${ZLINT_BIN}"
print_info >&2 "Found  : ev-checker : ${EV_CHECK_BIN}"
fi

if [ $VERBOSITY -gt 1 ]; then
print_info >&2 "OpenSSL Purpose ID  : '${KU_OPENSSL}'"
print_info >&2 "vfychain Purpose ID : '${KU_VFYCHAIN}'"
print_info >&2 "certutil Purpose ID : '${KU_CERTUTIL}'"
print_info >&2 "golang Purpose ID   : '${KU_GOLANG}'"
print_info >&2 "gnutls Purpose ID   : '${KU_GNUTLS}'"
fi

CA_CHAIN_FULL_PATH=""
if [ ! -z "${CA_CHAIN}" ]; then
  CA_CHAIN_FULL_PATH=$(realpath "${CA_CHAIN}")
fi

PEM_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).pem"
if ! openssl x509 -outform pem -in "${CERT}" -out "${PEM_FILE}" > /dev/null 2>&1; then
  usage "Failed to parse input file '${CERT}' as PEM certificate."
fi

if [ ! -z "${CA_CHAIN}" ]; then
PEM_CHAIN_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).chain.pem"
openssl x509 -outform pem -in "${CERT}" -out "${PEM_CHAIN_FILE}" > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
cat "${CA_CHAIN}" >> "${PEM_CHAIN_FILE}"
fi
fi

DER_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).der"
openssl x509 -outform der -in "${PEM_FILE}" -out "${DER_FILE}" > /dev/null 2>&1

#
## Determine tool versions
#

CERTTOOL_CAN_VERIFY="false"
CERTTOOL_VERSION=$(certtool --version | head -n1 | grep -Po '(?<=\s)[0-9\.]+$')
if version_gt $CERTTOOL_VERSION $CERTTOOL_MIN_VER; then
  CERTTOOL_CAN_VERIFY="true"
fi

if [ $VERBOSITY -gt 1 ]; then
  print_info "Detected certtool version ${CERTTOOL_VERSION}"
fi

OPENSSL_IS_OLD="true"
OPENSSL_VERSION_NUM=$(openssl version | grep -Po '(?<=OpenSSL\s)\d\.\d\.\d(?=[a-z]\s)')
OPENSSL_VERSION_EXT=$(openssl version | grep -Po '(?<=OpenSSL\s\d\.\d\.\d)[a-z](?=\s)')
OPENSSL_FULLVERSION="${OPENSSL_VERSION_NUM}${OPENSSL_VERSION_EXT}"
OPENSSL_REQ_VERSION="${OPENSSL_MIN_VERSION_NUM}${OPENSSL_MIN_VERSION_EXT}"
if [ "$OPENSSL_VERSION_NUM" == "$OPENSSL_MIN_VERSION_NUM" ] || version_gt $OPENSSL_VERSION_NUM $OPENSSL_MIN_VERSION_NUM; then
  REQ_EXT_NUMBER=$(printf '%d' "'$OPENSSL_MIN_VERSION_EXT")
  CUR_EXT_NUMBER=$(printf '%d' "'$OPENSSL_VERSION_EXT")
  if [ ${CUR_EXT_NUMBER} -ge ${REQ_EXT_NUMBER} ]; then
    OPENSSL_IS_OLD="false"
  fi
fi

if [ $VERBOSITY -gt 1 ]; then
  print_info "Detected OpenSSL version ${OPENSSL_FULLVERSION}"
fi

#
## Start linting output
#

lec=0
print_bold "Checking certificate '${CERT}' ..."

if [ "${PRINT_MODE}" == "true" ]; then
  OPENSSL_RAW=$(openssl x509 -in "${PEM_FILE}" -noout -text)
  print_data "${OPENSSL_RAW}"
fi

if [ "${OPENSSL_IS_OLD}" == "true" ]; then
  print_warn "OpenSSL version ${OPENSSL_FULLVERSION} is too old to perform some validation methods."
  if [ ! -z "${EV_HOST}" ] || [ ! -z "${OPENSSL_SECLVL}" ]; then
    print_warn "OpenSSL ${OPENSSL_FULLVERSION} does not support security level or hostname validation."
  fi
fi

if [ "${CERTTOOL_CAN_VERIFY}" != "true" ]; then
  print_warn "GnuTLS certtool version ${CERTTOOL_VERSION} is too old for verification."
fi

#
## zlint
#

if [ -e "${ZLINT_BIN}" ]; then
  if ! ZLINT_RAW=$(${ZLINT_BIN} -pretty "${PEM_FILE}"); then
    # NOTE: zlint appears to return a non-zero exit code even if no warnings are found
    print_info "zlint returned a non-zero exit code."
  fi
  ZLINT=$(echo "${ZLINT_RAW}" | grep -1 -i -P '\"result\"\:\s\"(info|warn|error|fatal)\"')
fi

#
## AWS cablint/certlint
#

AWS_LINTED="false"
AWS_CERTLINT_ERROR=""
AWS_CABLINT_ERROR=""
if check_ruby_version; then
  pushd ${AWS_CLINT_DIR} > /dev/null 2>&1
  if ! AWS_CERTLINT=$(ruby -I lib:ext bin/certlint "${DER_FILE}" 2>&1); then
    AWS_CERTLINT_ERROR=$(echo "${AWS_CERTLINT}" | tail -n1)
    print_warn "AWS certlint returned a non-zero exit code."
  fi
  if ! AWS_CABLINT=$(ruby -I lib:ext bin/cablint "${DER_FILE}" 2>&1); then
    AWS_CABLINT_ERROR=$(echo "${AWS_CABLINT}" | tail -n1)
    print_warn >&2 "AWS cablint returned a non-zero exit code."
  fi
  popd > /dev/null 2>&1
  AWS_LINTED="true"
elif hash ruby 2>/dev/null; then
  print_warn >&2 "Ruby v${RUBY_VERSION} is too old for AWS linting (requires Ruby >= v${RUBY_MIN_VERSION})."
else
  print_warn >&2 "Ruby is not installed; cannot run AWS linting (requires Ruby >= v${RUBY_MIN_VERSION})."
fi

#
## Globalsign certlint
#

err=0
pushd ${GS_CLINT_DIR} > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
  if ! GS_CERTLINT=$(./gs-certlint -issuer "${CA_CHAIN_FULL_PATH}" -cert "${PEM_FILE}"); then
    err=1
  fi
else
  if ! GS_CERTLINT=$(./gs-certlint -cert "${PEM_FILE}"); then
    err=1
  fi
fi
popd > /dev/null 2>&1
if [ $err -ne 0 ]; then
  print_warn >&2 "GlobalSign certlint returned a non-zero exit code."
fi

#
## x509lint
#

if ! X509LINT=$(LD_LIBRARY_PATH=${X509_DIR} ${X509_BIN} "${PEM_FILE}"); then
  print_warn >&2 "x509lint returned a non-zero exit code."
fi

##

EC=0
OPENSSL_ERR=0
OPENSSL_CRL_ERR=0
GNUTLS_ERR=0

if [ $VERBOSITY -gt 1 ]; then
  DEBUG_LEVEL=9999
fi

OPENSSL_EXTRA=""
GNUTLS_EXTRA=""
if [ ! -z "${EV_POLICY}" ]; then
  OPENSSL_EXTRA="${OPENSSL_EXTRA} -policy ${EV_POLICY}"
fi
if [ ! -z "${EV_HOST}" ]; then
  GNUTLS_EXTRA="${GNUTLS_EXTRA} --verify-hostname=${EV_HOST}"

  if [ "${OPENSSL_IS_OLD}" == "false" ]; then
    OPENSSL_EXTRA="${OPENSSL_EXTRA} -verify_hostname ${EV_HOST}"
    if [ ! -z "${OPENSSL_SECLVL}" ]; then
      OPENSSL_EXTRA="${OPENSSL_EXTRA} -auth_level ${OPENSSL_SECLVL}"
    fi
  fi
fi

if [ ! -z "${KU_GNUTLS}" ]; then
  GNUTLS_EXTRA="${GNUTLS_EXTRA} --verify-purpose=${KU_GNUTLS}"
fi

#
## OpenSSL verification
#

err=0
if [ ! -z "${CA_CHAIN}" ]; then
  if ! OPENSSL_OUT=$(openssl verify ${OPENSSL_ARGS} ${OPENSSL_EXTRA} -CAfile "${PEM_CHAIN_FILE}" "${PEM_FILE}" 2>&1); then
    err=1
  fi
else
  if ! OPENSSL_OUT=$(openssl verify ${OPENSSL_ARGS} ${OPENSSL_EXTRA} "${PEM_FILE}" 2>&1); then
    err=1
  fi
fi
if [ $err -ne 0 ]; then
  OPENSSL_ERR=1
  print_warn "OpenSSL verification returned a non-zero exit code." >&2
fi

#
## OpenSSL CRL verification
#

# TODO: Refactor to process CRL for every certificate in chain
# Functions could be added to download CA certificates from AIA URLs to build the chain as well.
# If we can get the CRL file (in PEM format) for each certificate in the chain, then we could use
# the 'openssl verify -crl_check_all' command to validate all of them.
CA_FILE=""
if CRL_URL=$(get_crl_http_from_pem "${PEM_FILE}"); then
  RAW_CRL_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).raw.crl"
  if ! wget -qO "${RAW_CRL_FILE}" "${CRL_URL}"; then
    # Failed to download CRL file
    if [ ! -z "${PEM_CHAIN_FILE}" ]; then
      CA_FILE="${PEM_CHAIN_FILE}"
    fi
    print_warn "Failed to download CRL from '${CRL_URL}'."
  else
    PEM_CRL_FILE=$(get_pem_file "${RAW_CRL_FILE}")
    TMP_CRL_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).tmp.crl"
    cat ${PEM_CHAIN_FILE} ${PEM_CRL_FILE} > ${TMP_CRL_FILE}
    rm ${VERBOSE_FLAG} -f "${PEM_CRL_FILE}"
    CA_FILE="${TMP_CRL_FILE}"
  fi
  rm ${VERBOSE_FLAG} -f "${RAW_CRL_FILE}"
fi

if [ ! -z "${CA_FILE}" ]; then
  if ! OPENSSL_CRLCHECK=$(openssl verify -crl_check -CAfile "${CA_FILE}" "${PEM_FILE}" 2>&1); then
    OPENSSL_CRL_ERR=1
  fi
else
  OPENSSL_CRL_ERR=1
  print_warn "Unable to check CRL revocation status; failed to obtain required CRL file."
#  if ! OPENSSL_CRLCHECK=$(openssl verify -crl_check_all "${PEM_FILE}" 2>&1); then
#    OPENSSL_CRL_ERR=1
#  fi
fi

#
## GnuTLS certtool
#

if [ "${CERTTOOL_CAN_VERIFY}" == "true" ]; then
  DEBUG_ARG=""
  if [ ${DEBUG_LEVEL} -gt 0 ]; then
    DEBUG_ARG="-d ${DEBUG_LEVEL}"
  fi
  err=0
  if [ ! -z "${CA_CHAIN}" ]; then
    if ! CERTTOOL_OUT=$(certtool ${DEBUG_ARG} --verify ${GNUTLS_EXTRA} --load-ca-certificate "${CA_CHAIN}" 2>&1 < "${PEM_FILE}"); then
      err=1
    fi
  else
    if ! CERTTOOL_OUT=$(certtool ${DEBUG_ARG} --verify ${GNUTLS_EXTRA} 2>&1 < "${PEM_FILE}"); then
      err=1
    fi
  fi
  if [ $err -ne 0 ]; then
    GNUTLS_ERR=1
    print_warn >&2 "GnuTLS certtool returned a non-zero exit code."
  fi
fi

###

#echo; print_header "Results:"
#print_header "---"

#
## OpenSSL
#

# Peform security level checks
CERT_BITS=$(openssl x509 -in "${PEM_FILE}" -text -noout | grep -Po '(?<=Public-Key:\s\()[0-9]+(?=\sbit\))')
CERT_ALGO=$(openssl x509 -in "${PEM_FILE}" -text -noout | grep -Po '(?<=Public\sKey\sAlgorithm:\s)([a-zA-Z]+)$')
if [ ! -z "${SECURITY_LEVEL}" ] && [ ! -z "${CERT_ALGO}" ] && [ ! -z "${CERT_BITS}" ]; then
  case "${CERT_ALGO}" in
    rsaEncryption)
      if [ $CERT_BITS -lt $RSA_MIN_BITS ]; then
        lec=1
        print_error "An RSA key of at least ${RSA_MIN_BITS} bits is required (certificate: ${CERT_BITS} bits)."
      else
        lec=0
        print_pass "RSA certificate key length of ${CERT_BITS} bits (${RSA_MIN_BITS} bits required)."
      fi
    ;;
  esac
fi

if [ ${OPENSSL_ERR} -eq 1 ]; then
  print_newline
  print_header "OpenSSL verify:"
  print_red "${OPENSSL_OUT}"
  EC=2
else
  if [ $lec -ne 0 ]; then
    print_newline
  fi
  lec=0
  print_pass "OpenSSL verify: certificate OK!"
fi

if [ ${OPENSSL_CRL_ERR} -eq 1 ]; then
  if [ ! -z "${OPENSSL_CRLCHECK}" ]; then
    print_newline
    text=$(echo "${OPENSSL_CRLCHECK}" | sed 's/'${PEM_FILE//\//\\/}'//')
    print_header "OpenSSL CRL verify:"
    print_yellow "${text}"
    if [[ 1 -gt $EC ]]; then
      EC=1
    fi
    lec=1
  else
    lec=0
  fi
else
  if [[ $lec -ne 0 ]]; then
    print_newline
  fi
  lec=0
  print_pass "OpenSSL verify: certificate CRL check OK!"
fi

#
## GnuTLS
#

if [ ${GNUTLS_ERR} -eq 1 ]; then
  print_newline
  print_header "GnuTLS certtool v${CERTTOOL_VERSION}:"
  print_red "${CERTTOOL_OUT}"
  if [[ 2 -gt $EC ]]; then
    EC=2
  fi
  lec=1
else
  if [[ $lec -ne 0 ]]; then
    print_newline
  fi
  lec=0
  if [ "${CERTTOOL_CAN_VERIFY}" == "true" ]; then
    print_pass "GnuTLS certtool v${CERTTOOL_VERSION}: certificate OK!"
  else
    print_warn "GnuTLS certtool is too old; unable to validate certificate."
  fi
fi

#
## z509lint
#

if [ ! -z "${X509LINT}" ]; then
  print_newline
  print_header "X.509 lint:"

  error_level=0
  IFS=$'\n'; for line in ${X509LINT}; do
    temp=$(echo "${line}" | grep -Po '(?<=^)(W|E|I|F|B)(?=\:\s)' | sort | head -n1)
    info=$(echo "${line}" | grep -Po '(?<=^(W|E|I|F|B)\:\s).*$')
    elvl=$(get_errlvl "${temp}")
    if [[ $elvl -gt $error_level ]]; then
      error_level=$elvl
    fi
    print_method=$(get_print_func "${temp}")
    ${print_method} "${info}"
  done

  lec=1
  if [[ $error_level -gt $EC ]]; then
    EC=${error_level}
  fi
else
  if [[ $lec -ne 0 ]]; then
    print_newline
  fi
  lec=0
  print_pass "X.509 lint: All certificate checks OK."
fi

#
## aws-certlint
#

if [ "${AWS_LINTED}" == "true" ]; then
  if [ ! -z "${AWS_CERTLINT}" ]; then
    if [ ! -z "${AWS_CERTLINT_ERROR}" ]; then
      print_newline >&2
      print_error >&2 "AWS certlint failed: ${AWS_CERTLINT_ERROR}"
    else
      print_newline
      print_header "AWS certificate lint:"

      error_level=0
      IFS=$'\n'; for line in ${AWS_CERTLINT}; do
        temp=$(echo "${line}" | grep -Po '(?<=^)(W|E|I|F|B|N)(?=\:\s)' | sort | head -n1)
        info=$(echo "${line}" | grep -Po '(?<=^(W|E|I|F|B|N)\:\s).*$')
        elvl=$(get_errlvl "${temp}")
        if [[ $elvl -gt $error_level ]]; then
          error_level=$elvl
        fi
        print_method=$(get_print_func "${temp}")
        ${print_method} "${info}"
      done

      lec=1
      if [[ $error_level -gt $EC ]]; then
        EC=${error_level}
      fi
    fi
  else
    if [[ $lec -ne 0 ]]; then
      print_newline
    fi
    lec=0
    print_pass "AWS certificate lint: certificate OK!"
  fi
fi

#
## aws-cablint
#

if [ "${AWS_LINTED}" == "true" ]; then
  if [ ! -z "${AWS_CABLINT}" ]; then
    if [ ! -z "${AWS_CABLINT_ERROR}" ]; then
      print_newline >&2
      print_error >&2 "AWS cablint failed: ${AWS_CABLINT_ERROR}"
    else
      print_newline
      print_header "AWS CA/B Forum lint:"

      error_level=0
      IFS=$'\n'; for line in ${AWS_CABLINT}; do
        temp=$(echo "${line}" | grep -Po '(?<=^)(W|E|I|F|B|N)(?=\:\s)' | sort | head -n1)
        info=$(echo "${line}" | grep -Po '(?<=^(W|E|I|F|B|N)\:\s).*$' | sed 's/'$(basename ${DER_FILE})'//')
        elvl=$(get_errlvl "${temp}")
        if [[ $elvl -gt $error_level ]]; then
          error_level=$elvl
        fi

        if echo "${info}" | grep -qP 'EV\scertificate\sidentified'; then
          EV_DETECTED="true"
        fi

        print_method=$(get_print_func "${temp}")
        ${print_method} "${info}"
      done

      lec=1
      if [[ $error_level -gt $EC ]]; then
        EC=${error_level}
      fi
    fi
  else
    if [[ $lec -ne 0 ]]; then
      print_newline
    fi
    lec=0
    print_pass "AWS CA/B Forum lint: All certificate checks OK."
  fi
fi

#
## zlint
#

if [ ! -z "${ZLINT}" ]; then
  print_newline
  print_header "ZLint:"
  IFS=$'\n'; for x in ${ZLINT}; do
    name=$(echo $x | grep -Po '(?<=\")[^\"]+(?=\"\:\s\{)')
    if [ ! -z "$name" ]; then
      add_zlint_lint "$name"
    fi
  done

  # parse zlint json results
  error_level=0
  for ((idx=0;idx<=$((${#zlint_names[@]}-1));idx++)); do
    zlint_name="${zlint_names[$idx]}"

    details=$(echo "${ZLINT_RAW}" | jq -r ".${zlint_name}.details")
    result=$(echo "${ZLINT_RAW}" | jq -r ".${zlint_name}.result")

    desc=$(${ZLINT_BIN} -list-lints-json | grep "$zlint_name" | grep -Po '(?<=\"description\"\:\")[^\"]+(?=\")')
    ref=$(${ZLINT_BIN} -list-lints-json | grep "$zlint_name" | grep -Po '(?<=\"citation\"\:\")[^\"]+(?=\")')

    if [ "${result}" == "info" ]; then
      result="notice"
    fi

    elvl=$(get_errlvl "${result}")
    if [[ $elvl -gt $error_level ]]; then
      error_level=$elvl
    fi

    print_method=$(get_print_func "${result}")
    print_method_raw=$(get_print_func_raw "${result}")
    if [ ! -z "${details}" ] && [ "${details}" != "null" ]; then
      ${print_method} "${details}"
    else
      ${print_method} "${desc}"
    fi

    if [ $VERBOSITY -gt 1 ]; then
    print_header "---"
    ${print_method_raw} "zlint name  : $zlint_name"
    ${print_method_raw} "result      : ${result}"
    if [ ! -z "${details}" ] && [ "${details}" != "null" ]; then
    ${print_method_raw} "details     : ${details}"
    fi
    if [ $VERBOSITY -gt 0 ]; then
    ${print_method_raw} "description : ${desc}"
    fi
    ${print_method_raw} "reference   : ${ref}"
    print_header "---"
    fi
  done

  lec=1
  if [[ $error_level -gt $EC ]]; then
    EC=${error_level}
  fi
else
  if [[ $lec -ne 0 ]]; then
    print_newline
  fi
  lec=0
  print_pass "ZLint: All certificate checks OK."
fi

#
## Golang
#

print_newline
print_header "Golang:"
for lint in ${GOLANG_LINTS}; do
  lint_name="${lint%.*}"
  lint_script="${lint}"
  result=""
  lint_error=0
  if [ -e "${lint_name}" ]; then
    if [ $VERBOSITY -gt 2 ]; then
      print_debug >&2 "Running Go binary ${lint_name} ..."
    fi
    lint_script="${lint_name}"
    if ! result=$(${lint_script} "${PEM_FILE}" "${PEM_CHAIN_FILE}" ${KU_GOLANG} "${EV_HOST}" 2>/dev/null); then
      lint_error=1
    fi
  elif [ $GOLANG_INSTALLED -ne 1 ]; then
    lint_error=1
  else
    if [ $VERBOSITY -gt 2 ]; then
      print_debug >&2 "Running Go script ${lint_name} ..."
    fi
    if ! result=$(go run $lint "${PEM_FILE}" "${PEM_CHAIN_FILE}" ${KU_GOLANG} "${EV_HOST}" 2>/dev/null); then
      lint_error=1
    fi
  fi
  if [[ $lint_error -eq 1 ]]; then
    lec=1
    if [ $GOLANG_INSTALLED -ne 1 ]; then
      print_warn "Go is not installed; cannot run '${lint_script}'."
    elif [ ! -z "${result}" ]; then
      print_error "${result}"
    else
      print_error "Go: Failed to run lint script '${lint_script}'."
    fi
    if [ $GOLANG_INSTALLED -eq 1 ] && [[ 2 -gt $EC ]]; then
      EC=2
    fi
  else
    lec=0
    print_pass "${result}"
  fi
done

#
## gs-certlint
#

if [ ! -z "${GS_CERTLINT}" ]; then
  print_newline
  error_level=0
  print_header "GlobalSign certlint:"
  IFS=$'\n'; for line in ${GS_CERTLINT}; do
    if echo "${line}" | grep -qP '^Processed\sCertificate\sType\:\sEV$'; then
      EV_DETECTED="true"
      print_info "EV certificate identified"
    fi

    temp=$(echo "${line}" | grep -Po '(?<=Priority\:\s)(Error|Warning|Info)' | sort | head -n1)
    print_method=$(get_print_func "${temp}")

    elvl=$(get_errlvl "${temp}")
    if [[ $elvl -gt $error_level ]]; then
      error_level=$elvl
    fi

    if echo "${line}" | grep -q "Message"; then
      info=$(echo "${line}" | grep -Po '(?<=Message\:\s).*$')
      ${print_method} "${info}"
    #else
      # TODO: Special handling for non-Message output?
      #print_normal "${line}"
    fi
  done

  lec=1
  if [[ $error_level -gt $EC ]]; then
    EC=${error_level}
  fi
else
  if [[ $lec -ne 0 ]]; then
    print_newline
  fi
  lec=0
  print_pass "GlobalSign certlint: certificate OK!"
fi

#
## Mozilla NSS
#

print_newline
if [ ! -z "${KU_CERTUTIL}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then
  print_header "Mozilla Network Security Service (NSS):"

  DB_PATH=$(mktemp -t -d nssdb.XXXXXXXXXX)

  cp ${PEM_FILE} ${DB_PATH}/cert.crt

  if [ ! -z "${PEM_CHAIN_FILE}" ]; then
    cp ${PEM_CHAIN_FILE} ${DB_PATH}/chain.tmp
  else
    touch ${DB_PATH}/chain.tmp
  fi

  # create temp. database
  certutil -N -d ${DB_PATH} --empty-password

  if [ "${NSS_VERIFY_CHAIN}" == "true" ]; then
    if [ $VERBOSITY -gt 0 ]; then
      print_info "Checking CA certificate chain..."
    fi
  fi

  # add all certificates from chain
  ca_count=0
  pushd ${DB_PATH} > /dev/null 2>&1
  awk 'BEGIN {c=0;} /BEGIN CERT/{c++} { print > "ca-cert." c ".pem"}' < chain.tmp
  popd > /dev/null 2>&1
  for c in ${DB_PATH}/*.pem; do
    ca_count=$((ca_count+1))

    crt_common_name=$(openssl x509 -noout -subject -nameopt multiline -in "${c}" | grep commonName | sed -n 's/ *commonName *= //p')

    if ! certutil -n "${crt_common_name}" -A -d ${DB_PATH} -a -i "${c}" -t CT,CT,CT; then
      ec=1
    elif [ "${NSS_VERIFY_CHAIN}" == "true" ]; then
      if ! result=$(certutil -V -n "${crt_common_name}" -u ${KU_CERTUTIL} -e -l -d ${DB_PATH} 2>&1); then
        if [[ 2 -gt $EC ]]; then
          EC=2
        fi
        lec=1
        print_red "CA ERROR : ${result}"
      else
        lec=0
        print_green "Valid CA : ${crt_common_name}: ${result}"
      fi
    fi
  done

  if [ "${NSS_VERIFY_CHAIN}" == "true" ]; then
    if [ $VERBOSITY -gt 0 ]; then
    print_info "Finished processing CA chain."
    fi
    print_newline
  fi

  # add entity certificate
  crt_common_name=$(openssl x509 -noout -subject -nameopt multiline -in "${DB_PATH}/cert.crt" | grep commonName | sed -n 's/ *commonName *= //p')
  if ! certutil -n "${crt_common_name}" -A -d ${DB_PATH} -a -i ${DB_PATH}/cert.crt -t P,P,P; then
    lec=1
    if [[ 1 -gt $EC ]]; then
      EC=1
    fi
  fi

  # check end-entity certificate
  if ! result=$(certutil -V -u ${KU_CERTUTIL} -e -l -d ${DB_PATH} -n "${crt_common_name}" 2>&1); then
    lec=1
    if [[ 2 -gt $EC ]]; then
      EC=2
    fi
    print_error "NSS certutil:"
    print_red "${result}"
  else
    lec=0
    print_pass "NSS certutil: ${crt_common_name}: ${result}"
  fi

  if [ ! -z "${KU_VFYCHAIN}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then
    if [ $lec -ne 0 ]; then
      print_newline
    fi

    err=0
    if [ ! -z "${EV_POLICY}" ]; then
      if ! result=$(vfychain -v ${VERBOSE_FLAG} -pp -u ${KU_VFYCHAIN} -o ${EV_POLICY} -d ${DB_PATH} "${crt_common_name}" 2>&1); then
        err=1
      fi
    else
      if ! result=$(vfychain -v ${VERBOSE_FLAG} -pp -u ${KU_VFYCHAIN} -d ${DB_PATH} "${crt_common_name}" 2>&1); then
        err=1
      fi
    fi
    if [[ $err -ne 0 ]]; then
      if [[ 2 -gt $EC ]]; then
        EC=2
      fi
      print_error "NSS vfychain: ${result}"
    else
      print_pass  "NSS vfychain: ${result}"
    fi
  fi

  if [ -e "${DB_PATH}" ]; then
    rm -rf ${VERBOSE_FLAG} ${DB_PATH}
  fi
#else
#  print_warn "Skipping Mozilla NSS verification."
fi

#
## ev-checker
#

if [ "${EV_DETECTED}" == "true" ] && [ ! -z "${EV_POLICY}" ] && [ ! -z "${EV_HOST}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then
print_newline
if [ "${NO_EV_CHECK}" != "true" ]; then
  print_header "EV Policy check:"
  if ! result=$(${EV_CHECK_BIN} -c ${PEM_CHAIN_FILE} -o "${EV_POLICY}" -h ${EV_HOST} 2>&1); then
    if [[ 2 -gt $EC ]]; then
      EC=2
    fi
    lec=1
    print_red  "${result}"
  else
    lec=0
    print_pass "${result}"
  fi

  print_newline
else
  print_warn "Skipping Extended Validation (EV) certificate validation."
  lec=1
  if [[ 1 -gt $EC ]]; then
    EC=1
  fi
fi
fi

if [ ! -z "${CA_FILE}" ]; then
  rm ${VERBOSE_FLAG} -f "${CA_FILE}"
fi
if [ ! -z "${PEM_FILE}" ]; then
  rm ${VERBOSE_FLAG} -f "${PEM_FILE}"
fi
if [ ! -z "${DER_FILE}" ]; then
  rm ${VERBOSE_FLAG} -f "${DER_FILE}"
fi

errorMsg="${errorMessages[${EC}]}"
print_method=$(get_print_func "${EC}")
if [ -z "${errorMsg}" ]; then
  exit_script 1 "Unexpected exit code."
fi

${print_method} "${errorMsg}"

if [[ ${EC} -le ${ERROR_LEVEL} ]]; then
  print_debug "Exit-code '${EC}' is below threshold; exiting with code zero..."
  EC=0
fi

exit ${EC}
