# pki-lint
```pki-lint``` is a simple Bash wrapper for a collection of x509 certificate and Public-key Infrastructure (PKI) checks. The script enables quick and easy identification of potential issues with generated x509 certificates.

Libraries (eg. OpenSSL, GnuTLS, etc.), languages (eg. Golang, C++, Python, etc.) and applications (eg. cURL, Git, Firefox, Chrome, etc.) often have a variety of differences in x509 certificate handling, including differences in the way certificates are validated. Despite extensive standards documentation, it is not uncommon to find different interpretations of those standards, either.

The primary purpose of this project is to identify potential compatibility issues prior to deploying a Public-key Infrastructure to production. It also provides an easy framework for adding additional checks in the future.


## Dependencies
The following third-party linters are used by this project:
- [aws-certlint](https://git.0x19e.net/security/aws-certlint.git)
- [gs-certlint](https://git.0x19e.net/security/gs-certlint.git)
- [x509lint](https://git.0x19e.net/security/x509lint.git)
- [ev-checker](https://git.0x19e.net/security/ev-checker.git)
- [zlint](https://git.0x19e.net/security/zmap-zlint.git)

The following packages are also required:
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

## Building sources manually
To compile all of the dependencies and linting modules you can call ```make``` directly, so long as you have all of the required compilers and libraries installed on your system.

For Debian and Debian-based distributions like Ubuntu with APT (Advanced Package Manager) installed, you can run the following commands to setup a build environment:
```bash
sudo apt-get install make gcc clang \
   gnutls-bin openssl git jq \
   ruby-dev golang-go libnspr4-dev \
   libcurl4-openssl-dev libnss3-dev \
   libssl-dev && \
sudo gem install simpleidn && \
sudo gem install public_suffix
```

Since the ```Makefile``` included in the top-level directory simply calls to ```lints/Makefile```, so for more control over the process it's best to run ```make``` from within the ```lints/``` subdirectory:
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

## Usage
To view usage information, run:
```bash
./lint.sh --help
```

## Lints
The collections of checks and thid-party modules used by this linter can be found in the ```lints/``` folder.

The basic folder structure for this project is shown in the diagram below:
```
pki-lint
  |
  |- lints/
  |   |
  |   |--- bin/
  |   |
  |   |--- golang/
  |   |
  |   |--- Makefile
  |
  |- Makefile
  |
  |- build.sh
  |
  |- lint.sh
```

The main files and directories are:
- ```lints/```: The top-level directory for all checks and thid-party modules.
- ```bin/```: Directory containing symlinks to compiled linting tools.
- ```golang```: Go / Golang scripts for performing simple compatibility checks. Each ```.go``` script in this directory is run by ```lint.sh```.
- ```Makefile```: The ```make``` configuration for building linting sources.
- ```build.sh```: The main build script for the project. Pulls down Git submodules and compiles all of the linting sources. This script will also try to resolve dependency packages for your system.
- ```lint.sh```: The main linting script. Calls individual lints and reports on the results.


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


## License
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Unpublished Copyright 2019 © Robert W. Baumgartner. All rights reserved.
