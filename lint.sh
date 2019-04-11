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

NO_COLOR="true"
CERTTOOL_MIN_VER="3.0.0"
VERBOSITY=0
DEBUG_LEVEL=0
NSS_VERIFY_CHAIN="false"
SECURITY_LEVEL=0
OPENSSL_SECLVL=2
OPENSSL_ARGS="-verbose -x509_strict -policy_print -policy_check"

OPENSSL_MIN_VERSION_NUM="1.1.0"
OPENSSL_MIN_VERSION_EXT="g"

hash openssl 2>/dev/null || { echo >&2 "You need to install openssl. Aborting."; exit 1; }
hash go 2>/dev/null || { echo >&2 "You need to install go. Aborting."; exit 1; }
hash git 2>/dev/null || { echo >&2 "You need to install git. Aborting."; exit 1; }
hash certtool 2>/dev/null || { echo >&2 "You need to install gnutls-bin. Aborting."; exit 1; }
hash jq 2>/dev/null || { echo >&2 "You need to install jq. Aborting."; exit 1; }
hash ruby 2>/dev/null || { echo >&2 "You need to install ruby-dev. Aborting."; exit 1; }
hash vfychain 2>/dev/null || { echo >&2 "You need to install libnss3-tools. Aborting."; exit 1; }

# define supported security levels
# level 0: 112 bits (RSA >= 2048  bits ; ECC >= 224 bits)
# level 1: 128 bits (RSA >= 3072  bits ; ECC >= 256 bits)
# level 2: 192 bits (RSA >= 7680  bits ; ECC >= 384 bits)
# level 3: 256 bits (RSA >= 15360 bits ; ECC >= 512 bits)
securityLevels=([0]=minimum [1]=medium [2]=high [3]=extreme)

# define table of EKU purpose arguments for various tools
certPurposes=([0]=client [1]=server [2]=mailsign [3]=mailencrypt [4]=ocsp [5]=anyCA)
opensslk_opts=([0]=sslclient [1]=sslserver [2]=smimesign [3]=smimeencrypt [4]= [5]=)
vfychain_opts=([0]=0 [1]=1 [2]=4 [3]=5 [4]=10 [5]=11)
certutil_opts=([0]=C [1]=V [2]=S [3]=R [4]=O [5]=A)
golangku_opts=([0]=2 [1]=1 [2]=4 [3]=4 [4]=9 [5]=)
gnutlsku_opts=([0]=1.3.6.1.5.5.7.3.2 [1]=1.3.6.1.5.5.7.3.1 [2]=1.3.6.1.5.5.7.3.4 [3]=1.3.6.1.5.5.7.3.4 [4]=1.3.6.1.5.5.7.3.9 [5]=)

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
  echo -e "\x1b[39;49;00m\x1b[31;01m${1}\x1b[39;49;00m"
  else
  echo "${1}"
  fi
}

print_yellow()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e "\x1b[39;49;00m\x1b[33;01m${1}\x1b[39;49;00m"
  else
  echo "${1}"
  fi
}

print_magenta()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e "\x1b[39;49;00m\x1b[35;01m${1}\x1b[39;49;00m"
  else
  echo "${1}"
  fi
}

print_cyan()
{
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e "\x1b[39;49;00m\x1b[36;01m${1}\x1b[39;49;00m"
  else
  echo "${1}"
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
      print_green >&2 "INFO: $@"
    else
      print_red       "ERROR: $@" 1>&2
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

    Performs various linting tests against the specified X.509 certificate.

    SYNTAX
            SCRIPT_NAME [OPTIONS] ARGUMENTS

    ARGUMENTS

     certificate             The certificate (in PEM format) to lint.

    OPTIONS

     -r, --root              Certificate is a root CA.
     -i, --intermediate      Certificate is an Intermediate CA.
     -s, --subscriber        Certificate is for an end-entity.

     -c, --chain <file>      Specifies a CA chain file to use.
     -o, --policy <oid>      Specifies an OID of a policy to test.
     -n, --hostname <name>   Specifies the hostname for validation.

     -u, --usage <purpose>   Specifies the certificate purpose to test for.
                             Supported options are:
                             - 0=client
                             - 1=server
                             - 2=mailsign
                             - 3=mailencrypt
                             - 4=ocsp
                             - 5=anyCA

     -l, --level <level>     Specify the required certificate security level.
                             Supported options are:
                             - 0=minimum (>= 112 bits) (default)
                             - 1=medium  (>= 128 bits)
                             - 2=high    (>= 192 bits)
                             - 3=extreme (>= 256 bits)

     -p, --print             Print the input certificate.
     -b, --colors            Print colorful output.
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

test_number_arg()
{
  local arg="$1"
  local argv="$2"

  test_arg "$arg" "$argv"

  if [ -z "$argv" ]; then
    argv="$arg"
  fi

  re='^[0-9]+$'
  if ! [[ $argv =~ $re ]]; then
    usage "Value is not a valid number: '$argv'."
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
  if ! `echo "$argv" | grep -qPo ${host_regex}`; then
    usage "Invalid hostname: '${argv}'"
  fi
}

DIR=$(get_root_dir)
CERT=""
CA_CERT="false"
X509_MODE=""
CA_CHAIN=""
EV_POLICY=""
EV_HOST=""
PRINT_MODE=""
OPT_PURPOSE=""
OPT_LEVEL=""

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

function get_purpose()
{
  if [ -z "$1" ]; then
    exit_script 1 "Purpose cannot be null."
  fi

  temp=$1
  re='^[0-9]+$'
  if [[ $temp =~ $re ]] ; then
    temp="${certPurposes[temp]}"
    if [ -z "${temp}" ]; then
      usage "'$1' is not mapped to a known purpose."
    fi
  fi
  if ! echo ${certPurposes[@]} | grep -q -w "$temp"; then
    usage "'$temp' is not a valid purpose."
  fi

  echo ${temp}
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
      OPT_PURPOSE=`get_purpose "$1"`
      shift
    ;;
    -l|--level)
      if [ ! -z "${OPT_LEVEL}" ]; then
        usage "Cannot specify multiple security levels."
      fi
      test_arg "$1" "$2"
      shift
      # try to convert argument to security level
      OPT_LEVEL=`get_level "$1"`
      shift
    ;;
    -b|--colors)
      NO_COLOR="false"
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

if [ ! -z "${OPT_LEVEL}" ]; then
  SECURITY_LEVEL="${OPT_LEVEL}"
fi
if [ ! -z "${SECURITY_LEVEL}" ]; then
  SECURITY_LEVEL=$(get_level "${SECURITY_LEVEL}")
  OPENSSL_SECLVL=$(get_openssl_seclvl "${SECURITY_LEVEL}")

  if [ $VERBOSITY -gt 1 ]; then
    print_cyan "INFO: Security level '${SECURITY_LEVEL}' (OpenSSL auth_level ${OPENSSL_SECLVL})"
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

if [ $VERBOSITY -gt 2 ]; then
print_cyan >&2 "OpenSSL Purpose ID  : '${KU_OPENSSL}'"
print_cyan >&2 "vfychain Purpose ID : '${KU_VFYCHAIN}'"
print_cyan >&2 "certutil Purpose ID : '${KU_CERTUTIL}'"
print_cyan >&2 "golang Purpose ID   : '${KU_GOLANG}'"
print_cyan >&2 "gnutls Purpose ID   : '${KU_GNUTLS}'"
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

if [ $VERBOSITY -gt 1 ]; then
  print_cyan "INFO: Detected certtool version ${CERTTOOL_VERSION}"
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
  print_cyan "INFO: Detected OpenSSL version ${OPENSSL_FULLVERSION}"
fi

if [ "${OPENSSL_IS_OLD}" == "true" ]; then
  print_yellow "WARNING: OpenSSL version ${OPENSSL_FULLVERSION} is too old to perform some validation methods."
  if [ ! -z "${EV_HOST}" ] || [ ! -z "${OPENSSL_SECLVL}" ]; then
    print_yellow "WARNING: OpenSSL ${OPENSSL_FULLVERSION} does not support security level or hostname validation."
  fi
fi

if [ "${CERTTOOL_CAN_VERIFY}" != "true" ]; then
  print_yellow "WARNING: GnuTLS certtool version ${CERTTOOL_VERSION} is too old for verification."
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

CA_CHAIN_FULL_PATH=""
if [ ! -z "${CA_CHAIN}" ]; then
  CA_CHAIN_FULL_PATH=$(realpath "${CA_CHAIN}")
fi

PEM_FILE="$(mktemp -t $(basename ${CERT}).XXXXXX).pem"
openssl x509 -outform pem -in "${CERT}" -out "${PEM_FILE}" > /dev/null 2>&1
if ! [ $? -eq 0 ]; then
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

lec=0
print_magenta "Checking certificate '${CERT}' ..."

if [ "${PRINT_MODE}" == "true" ]; then
  echo
  openssl x509 -in "${PEM_FILE}" -noout -text
  echo
fi

if [ -e "${ZLINT_BIN}" ]; then
ZLINT_RAW=$(${ZLINT_BIN} -pretty "${PEM_FILE}")
ZLINT=$(echo "${ZLINT_RAW}" | grep -1 -i -P '\"result\"\:\s\"(info|warn|error|fatal)\"')
if ! [ $? -eq 0 ]; then
  # NOTE: zlint appears to return a non-zero exit code even if no warnings are found
  print_cyan "INFO: zlint returned a non-zero exit code."
fi
fi

pushd ${AWS_CLINT_DIR} > /dev/null 2>&1
AWS_CERTLINT=$(ruby -I lib:ext bin/certlint "${DER_FILE}")
if ! [ $? -eq 0 ]; then
  print_yellow "WARNING: AWS certlint returned a non-zero exit code." >&2
fi
AWS_CABLINT=$(ruby -I lib:ext bin/cablint "${DER_FILE}")
if ! [ $? -eq 0 ]; then
  print_yellow "WARNING: AWS cablint returned a non-zero exit code." >&2
fi
popd > /dev/null 2>&1

pushd ${GS_CLINT_DIR} > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
  GS_CERTLINT=$(./gs-certlint -issuer "${CA_CHAIN_FULL_PATH}" -cert "${PEM_FILE}")
else
  GS_CERTLINT=$(./gs-certlint -cert "${PEM_FILE}")
fi
if ! [ $? -eq 0 ]; then
  print_yellow "WARNING: GlobalSign certlint returned a non-zero exit code." >&2
fi
popd > /dev/null 2>&1

X509LINT=$(${X509_BIN} "${PEM_FILE}")
if ! [ $? -eq 0 ]; then
  print_yellow "WARNING: x509lint returned a non-zero exit code." >&2
fi

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

if [ ! -z "${CA_CHAIN}" ]; then
  OPENSSL_OUT=$(openssl verify ${OPENSSL_ARGS} ${OPENSSL_EXTRA} -CAfile "${PEM_CHAIN_FILE}" "${PEM_FILE}" 2>&1)
else
  OPENSSL_OUT=$(openssl verify ${OPENSSL_ARGS} ${OPENSSL_EXTRA} "${PEM_FILE}" 2>&1)
fi
if ! [ $? -eq 0 ]; then
  OPENSSL_ERR=1
  print_yellow "WARNING: OpenSSL verification returned a non-zero exit code." >&2
fi

if [ ! -z "${CA_CHAIN}" ]; then
  OPENSSL_CRLCHECK=$(openssl verify -crl_check_all -CAfile "${PEM_CHAIN_FILE}" "${PEM_FILE}" 2>&1)
else
  OPENSSL_CRLCHECK=$(openssl verify -crl_check_all "${PEM_FILE}" 2>&1)
fi
if ! [ $? -eq 0 ]; then
  OPENSSL_CRL_ERR=1
fi

if [ "${CERTTOOL_CAN_VERIFY}" == "true" ]; then
  DEBUG_ARG=""
  if [ ${DEBUG_LEVEL} -gt 0 ]; then
    DEBUG_ARG="-d ${DEBUG_LEVEL}"
  fi
  if [ ! -z "${CA_CHAIN}" ]; then
  CERTTOOL_OUT=$(cat "${PEM_FILE}" | certtool ${DEBUG_ARG} --verify ${GNUTLS_EXTRA} --load-ca-certificate "${CA_CHAIN}" 2>&1)
  else
  CERTTOOL_OUT=$(cat "${PEM_FILE}" | certtool ${DEBUG_ARG} --verify ${GNUTLS_EXTRA} 2>&1)
  fi
  if ! [ $? -eq 0 ]; then
    GNUTLS_ERR=1
    print_yellow "WARNING: GnuTLS certtool returned a non-zero exit code." >&2
  fi
fi

#echo
#print_yellow "Results:"
#print_magenta "---"

################## OpenSSL

# Peform security level checks
CERT_BITS=$(openssl x509 -in "${PEM_FILE}" -text -noout | grep -Po '(?<=Public-Key:\s\()[0-9]+(?=\sbit\))')
CERT_ALGO=$(openssl x509 -in "${PEM_FILE}" -text -noout | grep -Po '(?<=Public\sKey\sAlgorithm:\s)([a-zA-Z]+)$')
if [ ! -z "${SECURITY_LEVEL}" ] && [ ! -z "${CERT_ALGO}" ] && [ ! -z "${CERT_BITS}" ]; then
  case "${CERT_ALGO}" in
    rsaEncryption)
      if [ $CERT_BITS -lt $RSA_MIN_BITS ]; then
        lec=1
        print_red "ERROR: Security level '${SECURITY_LEVEL}' requires an RSA key of at least ${RSA_MIN_BITS} bits (certificate: ${CERT_BITS} bits)."
      else
        lec=0
        print_green "OK: RSA certificate key length of ${CERT_BITS} bits (minimum for '${SECURITY_LEVEL}' security level: ${RSA_MIN_BITS} bits)."
      fi
    ;;
  esac
fi

if [ $lec -ne 0 ]; then
  echo
fi

if [ ${OPENSSL_ERR} -eq 1 ]; then
  print_magenta "openssl verify:"
  print_red "${OPENSSL_OUT}"
  EC=1
  lec=1
else
  lec=0
  print_green "openssl verify: certificate OK!"
fi

if [ $lec -ne 0 ]; then
  echo
fi

if [ ${OPENSSL_CRL_ERR} -eq 1 ]; then
  print_magenta "openssl CRL verify:"
  print_yellow "${OPENSSL_CRLCHECK}"
  EC=1
  lec=1
else
  lec=0
  print_green "openssl verify: certificate CRL check OK!"
fi

if [ $lec -ne 0 ]; then
  echo
fi

################## GnuTLS

if [ ${GNUTLS_ERR} -eq 1 ]; then
  print_magenta "GnuTLS certtool v${CERTTOOL_VERSION}:"
  print_red "${CERTTOOL_OUT}"
  EC=1
  lec=1
else
  lec=0
  if [ "${CERTTOOL_CAN_VERIFY}" == "true" ]; then
    print_green "GnuTLS certtool v${CERTTOOL_VERSION}: certificate OK!"
  else
    print_yellow "GnuTLS certtool is too old; unable to validate certificate."
  fi
fi

################## z509lint

if [ $lec -ne 0 ]; then
  echo
fi

if [ ! -z "${X509LINT}" ]; then
print_magenta "x509lint:"
print_red "${X509LINT}"
EC=1
lec=1
else
lec=0
print_green "x509lint: certificate OK"
fi

################## aws-certlint

if [ $lec -ne 0 ]; then
  echo
fi

if [ ! -z "${AWS_CERTLINT}" ]; then
print_magenta "aws-certlint:"
print_red "${AWS_CERTLINT}"
EC=1
lec=1
else
lec=0
print_green "aws-certlint: certificate OK"
fi

################## aws-cablint

if [ $lec -ne 0 ]; then
  echo
fi

if [ ! -z "${AWS_CABLINT}" ]; then
print_magenta "aws-cablint:"
print_red "${AWS_CABLINT}"
EC=1
lec=1
else
lec=0
print_green "aws-certlint: certificate OK"
fi

################## zlint

if [ $lec -ne 0 ]; then
  echo
fi

if [ ! -z "${ZLINT}" ]; then
print_magenta "zlint results:"
print_magenta "--"
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

  print_yellow "zlint name  : $zlint_name"
  print_yellow "result      : ${result}"
  if [ ! -z "${details}" ] && [ "${details}" != "null" ]; then
  print_yellow "details     : ${details}"
  fi
  if [ $VERBOSITY -gt 0 ]; then
  print_yellow "description : ${desc}"
  fi
  print_yellow "reference   : ${ref}"
  print_magenta "---"
done
EC=1
lec=1
else
lec=0
print_green "zlint: certificate OK"
fi

################## Golang

if [ $lec -ne 0 ]; then
  echo
fi

for lint in ${GOLANG_LINTS}; do
  result=$(go run $lint "${PEM_FILE}" "${PEM_CHAIN_FILE}" ${KU_GOLANG} "${EV_HOST}")
  print_cyan "${result}"
done

################## gs-certlint

echo
if [ ! -z "${GS_CERTLINT}" ]; then
print_magenta "gs-certlint:"
print_red "${GS_CERTLINT}"
EC=1
lec=1
else
lec=0
print_green "gs-certlint: certificate OK"
fi

################## NSS

if [ ! -z "${KU_CERTUTIL}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then

if [ $lec -ne 0 ]; then
  echo
fi

print_magenta "Mozilla Network Security Service (NSS):"

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
    echo "Checking CA certificate chain..."
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

  if ! certutil -n "${crt_common_name}" -A -d ${DB_PATH} -a -i "${c}" -t C,C,C; then
    ec=1
  elif [ "${NSS_VERIFY_CHAIN}" == "true" ]; then
    result=$(certutil -V -n "${crt_common_name}" -u ${KU_CERTUTIL} -e -l -d ${DB_PATH} 2>&1)
    if [ $? -ne 0 ]; then
      EC=1
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
  echo "Finished processing CA chain."
  fi
  echo
fi

# add entity certificate
crt_common_name=$(openssl x509 -noout -subject -nameopt multiline -in "${DB_PATH}/cert.crt" | grep commonName | sed -n 's/ *commonName *= //p')
if ! certutil -n "${crt_common_name}" -A -d ${DB_PATH} -a -i ${DB_PATH}/cert.crt -t P,P,P; then
  EC=1
fi

# check end-entity certificate
result=$(certutil -V -u ${KU_CERTUTIL} -e -l -d ${DB_PATH} -n "${crt_common_name}" 2>&1)
if [ $? -ne 0 ]; then
  EC=1
  lec=1
  print_red "NSS certutil FAILED:"
  print_red "${result}"
else
  lec=0
  print_green "NSS certutil OK: ${crt_common_name}: ${result}"
fi

if [ ! -z "${KU_VFYCHAIN}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then
  if [ $lec -ne 0 ]; then
    echo
  fi

  if [ ! -z "${EV_POLICY}" ]; then
    result=$(vfychain -v ${VERBOSE_FLAG} -pp -u ${KU_VFYCHAIN} -o ${EV_POLICY} -d ${DB_PATH} "${crt_common_name}" 2>&1)
  else
    result=$(vfychain -v ${VERBOSE_FLAG} -pp -u ${KU_VFYCHAIN} -d ${DB_PATH} "${crt_common_name}" 2>&1)
  fi
  if [ $? -ne 0 ]; then
    EC=1
    print_red "vfychain FAILED: ${result}"
  else
    print_green "vfychain OK: ${result}"
  fi
fi

if [ -e "${DB_PATH}" ]; then
rm -rf ${VERBOSE_FLAG} ${DB_PATH}
fi

fi

################## ev-checker

if [ ! -z "${EV_POLICY}" ] && [ ! -z "${EV_HOST}" ] && [ ! -z "${PEM_CHAIN_FILE}" ]; then
  if [ $lec -ne 0 ]; then
    echo
  fi
  print_magenta "EV policy check:"
  result=$(${EV_CHECK_BIN} -c ${PEM_CHAIN_FILE} -o "${EV_POLICY}" -h ${EV_HOST} 2>&1)
  if [ $? -ne 0 ]; then
    EC=1
    lec=1
    print_red "ev-checker FAILED:"
    print_red "${result}"
  else
    lec=0
    print_green "ev-checker OK: ${result}"
  fi
fi

rm ${VERBOSE_FLAG} ${DER_FILE} ${PEM_FILE}

exit ${EC}
