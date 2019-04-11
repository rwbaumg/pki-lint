# PKI Linting Notes

## OpenSSL
OpenSSL provides the ```openssl verify``` command for validating X.509 certificates.

The following security levels are defined by OpenSSL for certificate verification (taken from ```man SSL_CTX_set_security_level```).

**Certificates must be equivalent to *Level 2* or greater security in order to meet baseline requirements for certificate issuance.**

| Level   | Details       |
| :-----  | :----         |
| Level 0 | Everything is permitted. This retains compatibility with previous versions of OpenSSL. |
| Level 1 | The security level corresponds to a minimum of 80 bits of security. Any parameters offering below 80 bits of security are excluded. As a result RSA, DSA and DH keys shorter than 1024 bits and ECC keys shorter than 160 bits are prohibited. All export ciphersuites are prohibited since they all offer less than 80 bits of security. SSL version 2 is prohibited. Any ciphersuite using MD5 for the MAC is also prohibited. |
| Level 2 | Security level set to 112 bits of security. As a result RSA, DSA and DH keys shorter than 2048 bits and ECC keys shorter than 224 bits are prohibited.  In addition to the level 1 exclusions any ciphersuite using RC4 is also prohibited. SSL version 3 is also not allowed. Compression is disabled. |
| Level 3 | Security level set to 128 bits of security. As a result RSA, DSA and DH keys shorter than 3072 bits and ECC keys shorter than 256 bits are prohibited.  In addition to the level 2 exclusions ciphersuites not offering forward secrecy are prohibited. TLS versions below 1.1 are not permitted. Session tickets are disabled. |
| Level 4 | Security level set to 192 bits of security. As a result RSA, DSA and DH keys shorter than 7680 bits and ECC keys shorter than 384 bits are prohibited.  Ciphersuites using SHA1 for the MAC are prohibited. TLS versions below 1.2 are not permitted. |
| Level 5 | Security level set to 256 bits of security. As a result RSA, DSA and DH keys shorter than 15360 bits and ECC keys shorter than 512 bits are prohibited. |

---

To verify a certificate against security Level 2 requirements, you could run:
```bash
openssl verify -x509_strict -auth_level 2 /path/to/cert.crt 2>&1
```

To perform a more complete verification, you could run something like:
```bash
openssl verify -verbose \
               -show_chain \
               -x509_strict \
               -auth_level 2 \
               -verify_name default \
               -purpose sslserver \
               -verify_hostname test.example.com \
               -policy_print \
               -policy_check \
               -policy 2.23.140.1.2.2 \
               -CAfile /path/to/ca/chain.pem \
               /path/to/cert.crt
```

**Note that the ```auth_level``` argument is only available with newer versions of ```openssl```**

The following ```-purpose``` strings are supported by ```openssl verify```:
- ```sslclient```
- ```sslserver```
- ```nssslserver```
- ```smimesign```
- ```smimeencrypt```

The ```-verify_name``` option is used to set default verification policies, and is inferred from ```-purpose``` when not specified (making them functionally equivalent). The following names are supported:
- ```default```
- ```pkcs7```
- ```smime_sign```
- ```ssl_client```
- ```ssl_server```


## Key Purposes
Some possible Extended Key Usage (EKU) OIDs are listed below:

| Purpose            | Object Identifier (OID)        |
| :---               |    :----:                      |
| anyEKU             | ```2.5.29.37.0```              |
| serverAuth         | ```1.3.6.1.5.5.7.3.1```        |
| clientAuth         | ```1.3.6.1.5.5.7.3.2```        |
| codeSigning        | ```1.3.6.1.5.5.7.3.3```        |
| emailProtection    | ```1.3.6.1.5.5.7.3.4```        |
| timeStamping       | ```1.3.6.1.5.5.7.3.8```        |
| OCSPSigning        | ```1.3.6.1.5.5.7.3.9```        |
| msKernelCode       | ```1.3.6.1.4.1.311.61.1.1```   |
| msCodeInd          | ```1.3.6.1.4.1.311.2.1.21```   |
| msCodeCom          | ```1.3.6.1.4.1.311.2.1.22```   |
| id-kp-dvcs         | ```1.3.6.1.5.5.7.3.10```       |
| secureShellClient  | ```1.3.6.1.5.5.7.3.21```       |
| secureShellServer  | ```1.3.6.1.5.5.7.3.22```       |
| msDocSigning       | ```1.3.6.1.4.1.311.10.3.12```  |
| msSmartcardLogin   | ```1.3.6.1.4.1.311.20.2.2```   |
| msTimestamp        | ```1.3.6.1.4.1.311.10.3.2```   |
| BitLocker          | ```1.3.6.1.4.1.311.67.1.1```   |
| msEFS              | ```1.3.6.1.4.1.311.10.3.4```   |
| msEFSRecovery      | ```1.3.6.1.4.1.311.10.3.4.1``` |
| msDigitalRights    | ```1.3.6.1.4.1.311.10.5.1```   |
| msCTLSign          | ```1.3.6.1.4.1.311.10.3.1```   |
| scvpServer         | ```1.3.6.1.5.5.7.3.15```       |
| scvpClient         | ```1.3.6.1.5.5.7.3.16```       |
| EAPOVRPPP          | ```1.3.6.1.5.5.7.3.13```       |
| EAPOVRLAN          | ```1.3.6.1.5.5.7.3.14```       |
| adobePDFSigning    | ```1.2.840.113583.1.1.5```     |
| intelAMT           | ```2.16.840.1.113741.1.2.3```  |
| etsi-tslSigning    | ```0.4.0.2231.3.0```           |


## Mozilla NSS
The Mozilla Network Security Service (NSS) provides the following tools for certificate validation:
- ```vfychain```: Verifies certificate chains.
- ```certutil```: Manages keys and certificate in both NSS databases and other NSS tokens.

To validate a certificate chain using ```vfychain```, pass each CA certificate in the chain using ```-t /path/to/ca.crt```, and pass the PEM-encoded certificate to be validated using ```-a /path/to/cert.crt```. For example:
```bash
vfychain -v -pp -u 4 -a /path/to/emailsign.crt -t ca/root-ca.crt -t ca/int-ca.crt
```

The following certificate purposes are supported by the ```vfychain``` tool via the ```-u <purpose>``` option:

| Purpose                  | Code        |
| :---                     |    :----:   |
| SSL Client               | ```0```     |
| SSL Server               | ```1```     |
| SSL Step-Up              | ```2```     |
| SSL CA                   | ```3```     |
| Email Signer             | ```4```     |
| Email Recipient          | ```5```     |
| Object Signer            | ```6```     |
| Protected Object Signer  | ```9```     |
| OCSP Responder           | ```10```    |
| Any CA                   | ```11```    |

To validate a certificate contained in a NSS database, you can use the ```certutil``` command. For example, to test the certificate with friendly name ```test_cert``` for e-mail signing, you could run:
```bash
certutil -V -n "test_cert" -u S -e -l -d /path/to/nssdb
```

The following certificate purposes are supported by the ```certutil``` tool via the ```-u <purpose>``` option:

| Purpose         | Code        |
| :---            |    :----:   |
| SSL Client      | ```C```     |
| SSL Server      | ```V```     |
| SSL CA          | ```L```     |
| Any CA          | ```A```     |
| Verify CA       | ```V```     |
| Email Signer    | ```S```     |
| Email Recipient | ```R```     |
| OCSP Responder  | ```O```     |
| Object Signer   | ```J```     |


## Golang
Golang uses its own implementation for [X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509) certificate validation.

The following enumeration defines the EKU usage codes Golang uses internally:
```
ExtKeyUsageServerAuth = 1
ExtKeyUsageClientAuth = 2
ExtKeyUsageCodeSigning = 3
ExtKeyUsageEmailProtection = 4
ExtKeyUsageIPSECEndSystem = 5
ExtKeyUsageIPSECTunnel = 6
ExtKeyUsageIPSECUser = 7
ExtKeyUsageTimeStamping = 8
ExtKeyUsageOCSPSigning  = 9
ExtKeyUsageMicrosoftServerGatedCrypto = 10
ExtKeyUsageNetscapeServerGatedCrypto = 11
ExtKeyUsageMicrosoftCommercialCodeSigning = 12
ExtKeyUsageMicrosoftKernelCodeSigning = 13
```


## GnuTLS
The ```certtool``` utility provided by GnuTLS can be used to validate certificates.

**Note that ```certtool``` version below ```3.0.0``` do not support certificate validation.**

To display a certificate:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --certificate-info \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a certificate:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --verify \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a particular purpose, include the OID using the ```--verify-purpose <oid>``` option. For example:
```bash
cat /path/to/cert.crt \
  | certtool -d 9999 \
    --verify \
    --verify-hostname test.example.com \
    --verify-purpose 1.3.6.1.5.5.7.3.1 \
    --load-ca-certificate /path/to/ca/chain.pem
```

To verify a certificate chain:
```bash
cat /path/to/chain.pem | certtool --verify-chain
```

Note that you can use ```--infile <file>``` instead of piping the certificate to ```certtool```. The debug level can be between 0-9999, and controls how much debugging output is printed out.


## Technical Constraints
For a certificate to be technically constrained, it *MUST* contain an ```extendedKeyUsage``` extension defining the purposes for which it may be used. When an EKU extension is added to a Subordinate CA, the CA is restricted in which purposes it may issue certificates for.

According to the [CA/Browser Forum Baseline Requirements, section 7.1.5](https://github.com/cabforum/documents/blob/master/docs/BR.md#715-name-constraints):
> If the Subordinate CA Certificate includes the id-kp-serverAuth extended key usage, then the Subordinate CA Certificate MUST include the Name Constraints X.509v3 extension with constraints on dNSName, iPAddress and DirectoryName.

The [Mozilla Root Store Policy, section 5.3](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#53-intermediate-certificates) states the following:
> Intermediate certificates created after January 1, 2019, with the exception of cross-certificates that share a private key with a corresponding root certificate:
> - *MUST* contain an EKU extension; and,
> - *MUST NOT* include the ```anyExtendedKeyUsage``` KeyPurposeId; and,
> - *MUST NOT* include both the ```id-kp-serverAuth``` and ```id-kp-emailProtection``` KeyPurposeIds in the same certificate.

The [Mozilla Root Store Policy, section 5.3.1](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#531-technically-constrained) states:
> - If the certificate includes the ```id-kp-serverAuth``` extended key usage, then to be considered technically constrained, the certificate *MUST* be Name Constrained.
> - If the certificate includes the ```id-kp-emailProtection``` extended key usage, then to be considered technically constrained, it *MUST* include the Name Constraints X.509v3 extension with constraints on ```rfc822Name```, with at least one name in ```permittedSubtrees```, each such name having its ownership validated according to [section 3.2.2.4 of the Baseline Requirements](https://github.com/cabforum/documents/blob/master/docs/BR.md#3224-validation-of-domain-authorization-or-control).
> - The ```anyExtendedKeyUsage``` KeyPurposeId *MUST NOT* appear within the EKU extension.


## References
The following resources provide relavent standards documentation and examples for PKI testing:
- [ITU-T X.509](https://www.itu.int/itu-t/recommendations/rec.aspx?rec=X.509)
- [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing)
- [Mozilla Root Store Policy](https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md)
- [CA/Browser Forum: Baseline Requirements](https://github.com/cabforum/documents/blob/master/docs/BR.md)
- [CA/Browser Forum: Extended-Validation Guidelines](https://github.com/cabforum/documents/blob/master/docs/EVG.md)
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc6960)
- [RFC 4158: Internet X.509 Public Key Infrastructure: Certification Path Building](https://tools.ietf.org/html/rfc4158)
- [RFC 5913: Clearance Attribute and Authority Clearance Constraints Certificate Extension](https://tools.ietf.org/html/rfc5913)
- [RFC 5055: Server-Based Certificate Validation Protocol (SCVP)](https://tools.ietf.org/html/rfc5055)
- [RFC 6962: Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [Certificate Transparency](http://www.certificate-transparency.org/) ([GitHub](https://github.com/google/certificate-transparency))
- [Certificate Transparency Log Policy](https://github.com/chromium/ct-policy/blob/master/log_policy.md#certificate-transparency-log-policy)
