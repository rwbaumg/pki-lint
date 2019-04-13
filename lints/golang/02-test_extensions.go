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
    os.Exit(1)
  }

  var file string
  file = os.Args[1]

  /*
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
  */

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

  if len(cert.UnhandledCriticalExtensions) > 0 {
    fmt.Printf("Go: Found unhandled critical extensions:\n")
    for _, ext := range cert.UnhandledCriticalExtensions {
      fmt.Printf("    Extension OID: %s\n", ext.String());
     }
     os.Exit(1)
  }

  fmt.Printf("Go: No unhandled critical extensions.\n")
  os.Exit(0)
}
