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

     certificate           The certificate (in PEM format) to lint.

    OPTIONS

     -r, --root            Certificate is a root CA.
     -i, --intermediate    Certificate is an Intermediate CA.
     -s, --server          Certificate is for an end-entity.
     -v, --verbose         Make the script more verbose.
     -h, --help            Prints this usage.

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
    -s|--server)
      test_mode
      X509_MODE="x509lint-sub"
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
CLINT_DIR="${DIR}/lints/certlint"
GOLANG_LINTS="${DIR}/lints/golang/*.go"

DER_FILE="/tmp/$(basename ${CERT}).der"
PEM_FILE="/tmp/$(basename ${CERT}).pem"
openssl x509 -outform der -in "${CERT}" -out "${DER_FILE}" > /dev/null 2>&1
openssl x509 -outform pem -in "${CERT}" -out "${PEM_FILE}" > /dev/null 2>&1

pushd ${CLINT_DIR} > /dev/null 2>&1
CERTLINT=$(ruby -I lib:ext bin/certlint "${DER_FILE}")
popd > /dev/null 2>&1

X509LINT=$(${X509_BIN} "${PEM_FILE}")

EC=0

echo "Checking certificate '${CERT}' ..."

if [ ! -z "${CERTLINT}" ]; then
echo "certlint:"
echo "${CERTLINT}"
echo
EC=1
else
echo "certlint: certificate OK"
fi

if [ ! -z "${X509LINT}" ]; then
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

rm ${DER_FILE} ${PEM_FILE}

exit ${EC}
