package main

import (
  "os"
  "fmt"
  //"strconv"
  "io/ioutil"
  "log"
  "crypto/x509"
  "crypto/tls"
  "encoding/pem"
)

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
    fmt.Println("Usage: script.go <cert> [chain] [purpose]")
    return
  }

  var file string
  file = os.Args[1]

  /*
  var chain string
  var purpose x509.ExtKeyUsage

  if len(os.Args) >= 3 {
    chain = os.Args[2]
  }

  if len(os.Args) >= 4 {
    i, _ := strconv.Atoi(os.Args[3])
    //fmt.Printf("Go: Got raw purpose arg %d\n", i)
    purpose = x509.ExtKeyUsage(i)
    //fmt.Printf("Go: Using purpose %s\n", purpose)
  }
  */

  pemData, err := ioutil.ReadFile(file)
  if err != nil {
    log.Fatal(err)
  }

  block, rest := pem.Decode([]byte(pemData))
  if block == nil || len(rest) > 0 {
    log.Fatal("Certificate decoding error")
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
  } else {
    fmt.Printf("Go: No unhandled critical extensions (good!).\n")
  }
}
