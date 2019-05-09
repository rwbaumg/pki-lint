/*
 * [  0x19e Networks  ]
 * [ http://0x19e.net ]
 *
 * Golang x509 certificate verification test
 * Usage: script.go <cert> [chain] [purpose] [hostname]
 * Author: Robert W. Baumgartner <rwb@0x19e.net>
 */

package main

import (
  "os"
  "fmt"
  "strconv"
  "io/ioutil"
  "log"
  "crypto/x509"
  "crypto/tls"
  "encoding/pem"
)

func printDebug(level int, format string, a ...interface{}) (int, error) {
  verbose, _ := strconv.Atoi(os.Getenv("VERBOSITY"))

  // add debug level to arguments array
  args := a
  args = append(args, 0)
  copy(args[1:], args[0:])
  args[0] = level

  if (verbose >= level) {
    return fmt.Printf("Go: Debug(%d): " + format + "\n", args...)
  }

  return 0, nil
}

func loadPemChain(chainInput string) tls.Certificate {
  var cert tls.Certificate

  chainData, err := ioutil.ReadFile(chainInput)
  if err != nil {
    log.Fatal(err)
  }

  certPEMBlock := []byte(chainData)
  var certDERBlock *pem.Block
  for {
    certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
    if certDERBlock == nil {
      break
    }
    if certDERBlock.Type == "CERTIFICATE" {
      cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
    }
  }
  return cert
}

func checkCertificate(cert *x509.Certificate) {
  printDebug(2, "Checking certificate: %s", cert.Subject.CommonName)

  if len(cert.UnhandledCriticalExtensions) > 0 {
    fmt.Printf("Go: Found unhandled critical extension(s) in '%s':\n", cert.Subject.CommonName)
    for _, ext := range cert.UnhandledCriticalExtensions {
      fmt.Printf("\t   Extension OID: %s\n", ext.String());
     }
     os.Exit(1)
  }
  return
}

func getVerifyOpts(chain string, dnsName string, purpose x509.ExtKeyUsage) x509.VerifyOptions {
  // construct verification options
  opts := x509.VerifyOptions{
    DNSName: dnsName,
    KeyUsages: []x509.ExtKeyUsage{purpose}}

  if len(chain) > 0 {
    var chainCerts []*x509.Certificate

    // load all PEM-encoded certificates from the provided chain file
    certChain := loadPemChain(chain)
    printDebug(2, "Using PEM chain: %s", chain)

     // construct an array containing all chain certificates
    for _, cert := range certChain.Certificate {
      x509Cert, err := x509.ParseCertificate(cert)
      if err != nil {
        panic(err)
      }
      chainCerts = append(chainCerts, x509Cert)
    }

    if len(chainCerts) > 0 {
      // initialize certificate variables
      opts.Roots = x509.NewCertPool()
      opts.Intermediates = x509.NewCertPool()

      // parse chain certificates, assuming that the first in the array is the root
      // add the root certificate first
      var rootCert *x509.Certificate = chainCerts[len(chainCerts)-1]
      opts.Roots.AddCert(rootCert)
      printDebug(2, "Added Root CA: %s", rootCert.Subject)

      checkCertificate(rootCert)

      // add remaining certificates as intermediates
      var intCA *x509.Certificate
      for i := 1; i < len(chainCerts)-1; i = i + 1 {
        intCA = chainCerts[i]
        opts.Intermediates.AddCert(intCA)
        printDebug(2, "Added Intermediate CA: %s", intCA.Subject)

        checkCertificate(intCA)
      }
    }
  }

  return opts
}

func main() {
  // Read and parse the PEM certificate file
  if len(os.Args) < 2 {
    fmt.Printf("Usage: %s <cert> [chain] [purpose] [hostname]\n", os.Args[0])
    os.Exit(1)
  }

  var file string
  file = os.Args[1]

  var chain string
  if len(os.Args) >= 3 {
    chain = os.Args[2]
  }

  var purpose x509.ExtKeyUsage
  if len(os.Args) >= 4 {
    i, _ := strconv.Atoi(os.Args[3])
    purpose = x509.ExtKeyUsage(i)
    printDebug(2, "Checking EKU purpose ID: %d", purpose)
  }

  var dnsName string
  if len(os.Args) >= 5 {
    dnsName = os.Args[4]
    if len(dnsName) > 0 {
      printDebug(2, "Checking DNS Name: %s", dnsName)
    }
  }

  pemData, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatal(err)
  }

  block, rest := pem.Decode([]byte(pemData))
  if block == nil || len(rest) > 0 {
    log.Fatal("Go: Certificate decoding error")
  }

  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    log.Fatal(err)
  }

  // use getVerifyOpts to test certificate chain
  getVerifyOpts(chain, dnsName, purpose)

  // check the target certificate
  checkCertificate(cert)

  fmt.Printf("Go: No unhandled critical extensions.\n")
  os.Exit(0)
}
