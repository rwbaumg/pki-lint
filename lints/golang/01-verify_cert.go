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

func main() {
  // Read and parse the PEM certificate file
  if len(os.Args) < 2 {
    fmt.Println("Usage: script.go <cert> [chain] [purpose] [hostname]")
    return
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

  var dns_name string
  if len(os.Args) >= 5 {
    dns_name = os.Args[4]
    if len(dns_name) > 0 {
      printDebug(2, "Checking DNS Name: %s", dns_name)
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

  if purpose == 0 {
    // set default purpose
    // if we do not set it here golang will do it for us anyway
    purpose = x509.ExtKeyUsageServerAuth
  }

  // construct verification options
  opts := x509.VerifyOptions{
    Roots: x509.NewCertPool(),
    Intermediates: x509.NewCertPool(),
    DNSName: dns_name,
    KeyUsages: []x509.ExtKeyUsage{purpose}}

  if len(chain) > 0 {
    var chainCerts []*x509.Certificate

    // load all PEM-encoded certificates from the provided chain file
    certChain := loadPemChain(chain)
    if err != nil {
      log.Fatal(err)
    }
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
      // parse chain certificates, assuming that the first in the array is the root
      // add the root certificate first
      var rootCert *x509.Certificate = chainCerts[len(chainCerts)-1]
      opts.Roots.AddCert(rootCert)
      printDebug(2, "Added Root CA: %s", rootCert.Subject)

      // add remaining certificates as intermediates
      var intCA *x509.Certificate
      for i := 1; i < len(chainCerts)-1; i = i + 1 {
        intCA = chainCerts[i]
        opts.Intermediates.AddCert(intCA)
        printDebug(2, "Added Intermediate CA: %s", intCA.Subject)
      }
    }
  }

  // perform built-in Golang x509 certificate verification
  _, err = cert.Verify(opts)
  if err != nil {
    fmt.Printf("Go: Verify error: %s\n", err)
    return
  } else {
    fmt.Printf("Go: Certificate verification succeeded (good!).\n")
    return
  }
}
