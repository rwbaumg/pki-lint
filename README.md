# pki-lint
```pki-lint``` is a simple Bash wrapper for a collection of x509 certificate and Public-key Infrastructure (PKI) checks. The script enables quick and easy identification of potential issues with generated x509 certificates.

Libraries (eg. OpenSSL, GnuTLS, etc.), languages (eg. Golang, C++, Python, etc.) and applications (eg. cURL, Git, Firefox, Chrome, etc.) often have a variety of differences in x509 certificate handling, including differences in the way certificates are validated. Despite extensive standards documentation, it is not uncommon to find different interpretations of those standards, either.

The primary purpose of this project is to identify potential compatibility issues prior to deploying a Public-key Infrastructure to production.


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

## Usage
To view usage information, run:
```bash
./lint.sh --help
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


## License
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Unpublished Copyright 2019 © Robert W. Baumgartner. All rights reserved.
