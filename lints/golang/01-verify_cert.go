package main

import (
  "os"
  "fmt"
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
    fmt.Println("Usage: script.go <cert>")
    return
  }

  file := os.Args[1]
  chain := os.Args[2]

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

  opts := x509.VerifyOptions{Roots: x509.NewCertPool()}
  opts.Roots.AddCert(cert)

  if len(chain) > 0 {
    certChain := loadPemChain(chain)
    for _, cert := range certChain.Certificate {
      x509Cert, err := x509.ParseCertificate(cert)
      if err != nil {
        panic(err)
      }
      opts.Roots.AddCert(x509Cert)
    }
  }

  _, err = cert.Verify(opts)
  if err != nil {
    fmt.Printf("Go: Verify error: %s\n", err)
  } else {
    fmt.Printf("Go: Certificate verification succeeded (good!).\n")
  }
}
