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

VERBOSITY=0
DEBUG_LEVEL=0
NO_COLOR="false"
CERTTOOL_MIN_VER="3.0.0"

hash openssl 2>/dev/null || { echo >&2 "You need to install openssl. Aborting."; exit 1; }
hash go 2>/dev/null || { echo >&2 "You need to install go. Aborting."; exit 1; }
hash git 2>/dev/null || { echo >&2 "You need to install git. Aborting."; exit 1; }
hash certtool 2>/dev/null || { echo >&2 "You need to install gnutls-bin. Aborting."; exit 1; }

function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

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
      echo >&2 "INFO: $@"
    else
      echo "ERROR: $@" 1>&2
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

    Performs various linting tests against the speficied X.509 certificate.

    SYNTAX
            SCRIPT_NAME [OPTIONS] ARGUMENTS

    ARGUMENTS

     certificate             The certificate (in PEM format) to lint.

    OPTIONS

     -r, --root              Certificate is a root CA.
     -i, --intermediate      Certificate is an Intermediate CA.
     -s, --subscriber        Certificate is for an end-entity.

     -c, --chain <file>      Specifies a CA chain file to use.
     -e, --ev-policy <oid>   Specifies an OID to test for EV compliance.
     -n, --hostname <name>   Specifies the hostname for EV testing.

     -p, --print             Print the input certificate.
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

test_file_arg()
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

test_oid_arg()
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

test_host_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  host_regex='^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
  if ! `echo "$argv" | grep -Po ${host_regex}`; then
    usage "Invalid hostname: '${argv}'"
  fi
}

print_green()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[32;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
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

print_magenta()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[35;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
}

print_cyan()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[36;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
}

DIR=$(get_root_dir)
CERT=""
X509_MODE=""
CA_CHAIN=""
EV_POLICY=""
EV_HOST=""
PRINT_MODE=""

test_chain()
{
  if [ ! -z "${CA_CHAIN}" ]; then
    usage "Cannot specify multiple chain files."
  fi
}

test_ev_host()
{
  if [ ! -z "${EV_HOST}" ]; then
    usage "Cannot specify multiple hostnames."
  fi
}

test_cert()
{
  if [ ! -z "${CERT}" ]; then
    usage "Cannot specify multiple search terms."
  fi
}

test_mode()
{
  if [ ! -z "${X509_MODE}" ]; then
    usage "Cannot specify conflicting options."
  fi
}

test_ev_policy()
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

# process arguments
[ $# -gt 0 ] || usage
while [ $# -gt 0 ]; do
  case "$1" in
    -r|--root)
      test_mode
      X509_MODE="x509lint-root"
      shift
    ;;
    -i|--intermediate)
      test_mode
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
    -e|--ev-policy)
      test_ev_policy
      test_oid_arg "$1" "$2"
      shift
      EV_POLICY="$1"
      shift
    ;;
    -n|--ev-host)
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
    -h|--help)
      usage
    ;;
    -v|--verbose)
      ((VERBOSITY++))
      shift
    ;;
    *)
      test_cert
      test_file_arg "$1"
      CERT="$1"
      shift
    ;;
  esac
done

if [ ! -z "${EV_POLICY}" ] && [ -z "${CA_CHAIN}" ]; then
  usage "Must supply CA chain for EV policy testing."
fi
if [ ! -z "${EV_POLICY}" ] && [ -z "${EV_HOST}" ]; then
  usage "Must supply hostname for EV policy testing."
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
if [ $VERBOSITY -gt 1 ]; then
  VERBOSE_FLAG="-v"
fi

CERTTOOL_CAN_VERIFY="false"
CERTTOOL_VERSION=$(certtool --version | head -n1 | grep -Po '(?<=\s)[0-9\.]+$')
if version_gt $CERTTOOL_VERSION $CERTTOOL_MIN_VER; then
  CERTTOOL_CAN_VERIFY="true"
fi

X509_BIN="${DIR}/lints/x509lint/${X509_MODE}"
ZLINT_BIN="${DIR}/lints/bin/zlint"
AWS_CLINT_DIR="${DIR}/lints/aws-certlint"
GS_CLINT_DIR="${DIR}/lints/gs-certlint"
EV_CHECK_BIN="${DIR}/lints/ev-checker/ev-checker"
GOLANG_LINTS="${DIR}/lints/golang/*.go"

if [ ! -e "${X509_BIN}" ]; then
  usage "Missing required binary (did you build it?): lints/x509lint/${X509_MODE}"
fi
if [ ! -e "${EV_CHECK_BIN}" ]; then
  usage "Missing required binary (did you build it?): lints/ev-checker/ev-checker"
fi
if [ ! -e "${AWS_CLINT_DIR}/bin/certlint" ]; then
  usage "Missing required binary (did you build it?): lints/aws-certlint/bin/certlint"
fi
if [ ! -e "${ZLINT_BIN}" ]; then
  usage "Missing required binary (did you build it?): lints/bin/zlint"
fi

PEM_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).pem"
PEM_CHAIN_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).chain.pem"
openssl x509 -outform pem -in "${CERT}" -out "${PEM_FILE}" > /dev/null 2>&1
if ! [ $? -eq 0 ]; then
  usage "Failed to parse input file '${CERT}' as PEM certificate."
fi

openssl x509 -outform pem -in "${CERT}" -out "${PEM_CHAIN_FILE}" > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
cat "${CA_CHAIN}" >> "${PEM_CHAIN_FILE}"
fi

DER_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).der"
openssl x509 -outform der -in "${PEM_FILE}" -out "${DER_FILE}" > /dev/null 2>&1

echo "Checking certificate '${CERT}' ..."

if [ "${PRINT_MODE}" == "true" ]; then
  echo
  openssl x509 -in "${PEM_FILE}" -noout -text
  echo
fi

pushd ${AWS_CLINT_DIR} > /dev/null 2>&1
AWS_CERTLINT=$(ruby -I lib:ext bin/certlint "${DER_FILE}")
if ! [ $? -eq 0 ]; then
  echo >&2 "WARNING: AWS certlint returned a non-zero exit code."
fi
AWS_CABLINT=$(ruby -I lib:ext bin/cablint "${DER_FILE}")
if ! [ $? -eq 0 ]; then
  echo >&2 "WARNING: AWS cablint returned a non-zero exit code."
fi
popd > /dev/null 2>&1

pushd ${GS_CLINT_DIR} > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
  GS_CERTLINT=$(./gs-certlint -issuer "${CA_CHAIN}" -cert "${PEM_FILE}")
else
  GS_CERTLINT=$(./gs-certlint -cert "${PEM_FILE}")
fi
if ! [ $? -eq 0 ]; then
  echo >&2 "WARNING: GlobalSign certlint returned a non-zero exit code."
fi
popd > /dev/null 2>&1

X509LINT=$(${X509_BIN} "${PEM_FILE}")
if ! [ $? -eq 0 ]; then
  echo >&2 "WARNING: x509lint returned a non-zero exit code."
fi

if [ -e "${ZLINT_BIN}" ]; then
ZLINT_RAW=$(${ZLINT_BIN} -pretty "${PEM_FILE}")
ZLINT=$(echo "${ZLINT_RAW}" | grep -1 -i -P '\"result\"\:\s\"(info|warn|error|fatal)\"')
if ! [ $? -eq 0 ]; then
  echo >&2 "WARNING: zlint returned a non-zero exit code."
fi
fi

EC=0

OPENSSL_ERR=0
GNUTLS_ERR=0

if [ $VERBOSITY -gt 1 ]; then
  DEBUG_LEVEL=9999
fi

if [ ! -z "${CA_CHAIN}" ]; then
  OPENSSL_OUT=$(openssl verify -verbose -x509_strict -policy_print -CAfile "${PEM_CHAIN_FILE}" "${PEM_FILE}" 2>&1)
else
  OPENSSL_OUT=$(openssl verify -verbose -x509_strict -policy_print "${PEM_FILE}" 2>&1)
fi
if ! [ $? -eq 0 ]; then
  OPENSSL_ERR=1
  echo >&2 "WARNING: OpenSSL verification returned a non-zero exit code."
fi

if [ "${CERTTOOL_CAN_VERIFY}" == "true" ]; then
  DEBUG_ARG=""
  if [ ${DEBUG_LEVEL} -gt 0 ]; then
    DEBUG_ARG="-d ${DEBUG_LEVEL}"
  fi
  if [ ! -z "${CA_CHAIN}" ]; then
  CERTTOOL_OUT=$(cat "${PEM_FILE}" | certtool ${DEBUG_ARG} --verify --load-ca-certificate "${PEM_CHAIN_FILE}" 2>&1)
  else
  CERTTOOL_OUT=$(cat "${PEM_FILE}" | certtool ${DEBUG_ARG} --verify 2>&1)
  fi
  if ! [ $? -eq 0 ]; then
    GNUTLS_ERR=1
    echo >&2 "WARNING: GnuTLS certtool returned a non-zero exit code."
  fi
else
  echo >&2 "WARNING: GnuTLS certtool version ${CERTTOOL_VERSION} is too old for verification."
fi

echo
echo "Results:"
echo "---"

if [ ${OPENSSL_ERR} -eq 1 ]; then
  echo
  echo "openssl verify:"
  echo "${OPENSSL_OUT}"
  echo
  EC=1
else
  echo "openssl verify: certificate OK!"
fi

if [ ${GNUTLS_ERR} -eq 1 ]; then
  echo
  echo "GnuTLS certtool v${CERTTOOL_VERSION}:"
  echo "${CERTTOOL_OUT}"
  echo
  EC=1
else
  echo "GnuTLS certtool v${CERTTOOL_VERSION}: certificate OK!"
fi

if [ ! -z "${X509LINT}" ]; then
echo "x509lint:"
echo "${X509LINT}"
echo
EC=1
else
echo "x509lint: certificate OK"
fi

if [ ! -z "${AWS_CERTLINT}" ]; then
echo "aws-certlint:"
echo "${AWS_CERTLINT}"
echo
EC=1
else
echo "aws-certlint: certificate OK"
fi

if [ ! -z "${AWS_CABLINT}" ]; then
echo "aws-cablint:"
echo "${AWS_CABLINT}"
echo
EC=1
else
echo "aws-certlint: certificate OK"
fi

if [ ! -z "${ZLINT}" ]; then
echo "zlint results:"
echo "--"
IFS=$'\n'; for x in ${ZLINT}; do
  name=$(echo $x | grep -Po '(?<=\")[^\"]+(?=\"\:\s\{)')
  if [ ! -z "$name" ]; then
    add_zlint_lint "$name"
  fi
done

# parse zlint json results
for ((idx=0;idx<=$((${#zlint_names[@]}-1));idx++)); do
  zlint_name="${zlint_names[$idx]}"

  details=$(echo "${ZLINT_RAW}" | jq -r ".${zlint_name}.details")
  result=$(echo "${ZLINT_RAW}" | jq -r ".${zlint_name}.result")

  desc=$(${ZLINT_BIN} -list-lints-json | grep "$zlint_name" | grep -Po '(?<=\"description\"\:\")[^\"]+(?=\")')
  ref=$(${ZLINT_BIN} -list-lints-json | grep "$zlint_name" | grep -Po '(?<=\"citation\"\:\")[^\"]+(?=\")')

  echo "zlint name  : $zlint_name"
  echo "result      : ${result}"
  if [ ! -z "${details}" ] && [ "${details}" != "null" ]; then
  echo "details     : ${details}"
  fi
  if [ $VERBOSITY -gt 0 ]; then
  echo "description : ${desc}"
  fi
  echo "reference   : ${ref}"
  echo "---"
done

echo
EC=1
else
echo "zlint: certificate OK"
fi

for lint in ${GOLANG_LINTS}; do
  go run $lint ${PEM_FILE}
done

if [ ! -z "${GS_CERTLINT}" ]; then
echo
echo "gs-certlint:"
echo "${GS_CERTLINT}"
EC=1
else
echo "gs-certlint: certificate OK"
fi

if [ ! -z "${EV_POLICY}" ]; then
  echo
  echo "EV policy check:"
  ${EV_CHECK_BIN} -c ${PEM_CHAIN_FILE} -o "${EV_POLICY}" -h ${EV_HOST}
  if ! [ $? -eq 0 ]; then
    echo >&2 "WARNING: ev-checker returned a non-zero exit code."
  fi
fi

rm ${VERBOSE_FLAG} ${DER_FILE} ${PEM_FILE}

exit ${EC}
