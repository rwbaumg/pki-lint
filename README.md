# pki-lint
X.509 certificate linter

## Introduction
The ```pki-lint``` utility is a framework and wrapper for the linting of Public-key Infrastructure (PKI) [X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509) certificates. The included GNU/Linux Bash script, ```lint.sh```, enables quick and easy identification of potential issues with generated x509 certificates. The ```lint.sh``` script also doubles as a wrapper for a number of third-party certificate linters, and enables running a large number of compliance checks with a single command.

Libraries (eg. [OpenSSL](https://www.openssl.org/), [GnuTLS](https://www.gnutls.org/), etc.), languages (eg. [Golang](https://golang.org), [C++](https://isocpp.org/), etc.) and applications (eg. [cURL](https://curl.haxx.se/), [Git](https://git-scm.com/), [Firefox](https://www.mozilla.org/), [Chrome](https://www.google.com/chrome/), etc.) often have a variety of differences in [X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509) certificate handling, including differences in the way certificates are validated. Despite extensive standards documentation, it is not uncommon to find different interpretations of those standards, either.

The primary purpose of this project is to identify potential compatibility issues prior to deploying a Public-key Infrastructure into production. It also provides a basic framework for adding additional checks in the future.

---

## Dependencies
The following third-party linting tools are used by this project:
- [aws-certlint](https://git.0x19e.net/security/aws-certlint.git)
- [gs-certlint](https://git.0x19e.net/security/gs-certlint.git)
- [x509lint](https://git.0x19e.net/security/x509lint.git)
- [ev-checker](https://git.0x19e.net/security/ev-checker.git)
- [zlint](https://git.0x19e.net/security/zmap-zlint.git)

The following extra packages are also required
- Golang ```go``` ≥ v1.3
- Ruby ```ruby``` & ```ruby-dev``` ≥ v2.1, and
- Ruby Gems ```simpleidn``` & ```public_suffix```

Running the ```build.sh``` script will try to install missing dependencies for you.
Note that only the Debian-based package manager APT is currently supported.


## Installation
To initialize required modules and compile dependencies, run:
```bash
./build.sh
```

If you encounter errors building module sources you can use ```--verbose``` to get some basic debugging information:
```bash
./build.sh --verbose
```


## Usage
In order to select the appropriate tests, you must specify the type of the certificate being checked. The following certificate types are currently supported:
- Root CA certificates
- Intermediate CA certificates
- End-entity / subscriber certificates

To check an end-entity certificate, pass the full path to the PEM-encoded certificate file along with the appropriate type switch (ie. ```--subscriber```):
```bash
./lint.sh --subscriber /path/to/certificate.pem
```

To print the certificate being tested use the ```--print``` switch:
```bash
./lint.sh --subscriber /path/to/certificate.pem --print
```

To view extended usage information, run:
```bash
./lint.sh --help
```


## Lints
The collection of checks and third-party modules used by ```lint.sh``` linter can be found in the ```lints/``` folder.

The basic folder structure is shown in the diagram below:
```
pki-lint/
  |
  |- --lints/
  |     |
  |     |--- bin/
  |     |
  |     |--- golang/
  |     |
  |     |--- Makefile
  |
  |--- Makefile
  |
  |--- build.sh
  |
  |--- lint.sh
```

The main files and directories are:
- ```lints/```: The top-level directory for all checks and third-party modules.
- ```bin/```: Directory containing symlinks to compiled linting tools.
- ```golang```: Golang ```.go``` scripts for performing simple compatibility checks. Each ```.go``` script in this directory is run by ```lint.sh```.
- ```Makefile```: The ```make``` configuration for building linting module sources.
- ```build.sh```: The main build script for the project. Pulls down Git submodules and compiles all of the linting sources. This script will also try to resolve dependency packages for your system.
- ```lint.sh```: The main linting script. Calls individual lints and reports on the results.


## Building sources manually
To compile all of the dependencies and linting modules you can call ```make``` directly, so long as you have all of the required compilers and libraries installed on your system.

First, you must pull down all of the Git submodules referenced by the ```.gitmodules``` file. To do so, run:
```bash
git submodule init && \
git submodule update --recursive
```

For Debian and Debian-based distributions (e.g Ubuntu) with APT (Advanced Package Manager) installed, you can run the following commands to setup a build environment:
```bash
sudo apt-get install make gcc clang \
   gnutls-bin openssl git jq \
   ruby-dev golang-go libnspr4-dev \
   libcurl4-openssl-dev libnss3-dev \
   libnss3-tools libssl-dev && \
sudo gem install simpleidn && \
sudo gem install public_suffix
```

The ```Makefile``` included in the top-level directory simply calls to ```lints/Makefile```. For more control over the process, it's best to run ```make``` from within the ```lints/``` subdirectory:
```bash
cd lints/
```

To get a list of available ```Makefile``` targets, you can use the included ```list``` target:
```bash
make list
```

To run ```make``` with some additional debugging information, run:
```bash
make --debug=v all
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


## License
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Unpublished Copyright 2019 © Robert W. Baumgartner. All rights reserved.
