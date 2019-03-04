#!/bin/bash
#
# [ 0x19e Networks ]

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
     -h, --hostname <name>   Specifies the hostname for EV testing.

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
}

NO_COLOR="false"

print_green()
{
  if [ "${SILENT}" != "true" ]; then
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[32;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
  fi
}

print_red()
{
  if [ "${SILENT}" != "true" ]; then
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[31;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
  fi
}

print_yellow()
{
  if [ "${SILENT}" != "true" ]; then
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[33;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
  fi
}

print_magenta()
{
  if [ "${SILENT}" != "true" ]; then
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[35;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
  fi
}

print_cyan()
{
  if [ "${SILENT}" != "true" ]; then
  if [ "${NO_COLOR}" == "false" ]; then
  echo -e >&2 "\x1b[39;49;00m\x1b[36;01m${1}\x1b[39;49;00m"
  else
  echo >&2 "${1}"
  fi
  fi
}

CERT=""
VERBOSITY=0
X509_MODE=""

## Resolve root directory
# DIR=`dirname $0`
# DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  # if $SOURCE was a relative symlink, we need to resolve it
  # relative to the path where the symlink file was located
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

#CERT="$1"
#if [ ! -e "${CERT}" ]; then
#  echo >&2 "Usage: $1 <certificate>"
#  exit 1
#fi

test_mode()
{
  if [ ! -z "${X509_MODE}" ]; then
    usage "Cannot specify conflicting options."
  fi
}

CA_CHAIN=""
EV_POLICY=""
EV_HOST=""

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
      if [ ! -z "${CA_CHAIN}" ]; then
        usage "Cannot specify multiple chain files."
      fi
      test_file_arg "$1" "$2"
      shift
      CA_CHAIN="$1"
      shift
    ;;
    -e|--ev-policy)
      if [ ! -z "${EV_POLICY}" ]; then
        usage "Cannot specify multiple EV policies."
      fi
      test_arg "$1" "$2"
      shift
      EV_POLICY="$1"
      shift
    ;;
    -h|--ev-host)
      if [ ! -z "${EV_HOST}" ]; then
        usage "Cannot specify multiple hostnames."
      fi
      test_arg "$1" "$2"
      shift
      EV_HOST="$1"
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
        usage "Cannot specify multiple search terms."
      fi
      test_arg "$1"
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

X509_BIN="${DIR}/lints/x509lint/${X509_MODE}"
AWS_CLINT_DIR="${DIR}/lints/aws-certlint"
GS_CLINT_DIR="${DIR}/lints/gs-certlint"
EV_CHECK_BIN="${DIR}/lints/ev-checker/ev-checker"
GOLANG_LINTS="${DIR}/lints/golang/*.go"

# $(realpath --relative-to="$(pwd)" "${BIN}

if [ ! -e "${X509_BIN}" ]; then
  usage "Missing required binary (did you build it?): lints/x509lint/${X509_MODE}"
fi
if [ ! -e "${EV_CHECK_BIN}" ]; then
  usage "Missing required binary (did you build it?): lints/ev-checker/ev-checker"
fi
if [ ! -e "${AWS_CLINT_DIR}/bin/certlint" ]; then
  usage "Missing required binary (did you build it?): lints/aws-certlint/bin/certlint"
fi

PEM_FILE="/tmp/$(basename ${CERT}).pem"
PEM_CHAIN_FILE="/tmp/$(basename ${CERT}).chain.pem"
openssl x509 -outform pem -in "${CERT}" -out "${PEM_FILE}" > /dev/null 2>&1
openssl x509 -outform pem -in "${CERT}" -out "${PEM_CHAIN_FILE}" > /dev/null 2>&1
if [ ! -z "${CA_CHAIN}" ]; then
cat "${CA_CHAIN}" >> "${PEM_CHAIN_FILE}"
fi

DER_FILE="/tmp/$(basename ${CERT}).der"
openssl x509 -outform der -in "${PEM_FILE}" -out "${DER_FILE}" > /dev/null 2>&1

pushd ${AWS_CLINT_DIR} > /dev/null 2>&1
AWS_CERTLINT=$(ruby -I lib:ext bin/certlint "${DER_FILE}")
popd > /dev/null 2>&1

X509LINT=$(${X509_BIN} "${PEM_FILE}")

EC=0

echo "Checking certificate '${CERT}' ..."

if [ ! -z "${AWS_CERTLINT}" ]; then
echo "aws-certlint:"
echo "${AWS_CERTLINT}"
EC=1
else
echo "aws-certlint: certificate OK"
fi

if [ ! -z "${X509LINT}" ]; then
echo
echo "x509lint:"
echo "${X509LINT}"
echo
EC=1
else
echo "x509lint: certificate OK"
fi

#echo "Golang lints:"
for lint in ${GOLANG_LINTS}; do
  go run $lint ${PEM_FILE}
done

if [ ! -z "${EV_POLICY}" ]; then
  echo
  echo "EV policy check:"
  ${EV_CHECK_BIN} -c ${PEM_CHAIN_FILE} -o "${EV_POLICY}" -h ${EV_HOST}
fi

rm ${DER_FILE} ${PEM_FILE}

exit ${EC}
