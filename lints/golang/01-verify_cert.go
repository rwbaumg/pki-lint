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
    fmt.Println("Usage: script.go <cert> [chain] [purpose]")
    return
  }

  var file string
  var chain string
  var purpose x509.ExtKeyUsage

  file = os.Args[1]

  if len(os.Args) >= 3 {
    chain = os.Args[2]
  }

  if len(os.Args) >= 4 {
    var i interface{} = os.Args[3]
    kp, _ := i.(x509.ExtKeyUsage)
    purpose = kp
  }

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

  if purpose == 0 {
    purpose=x509.ExtKeyUsageServerAuth
  }

  opts := x509.VerifyOptions{
    Roots: x509.NewCertPool(),
    Intermediates: x509.NewCertPool(),
    KeyUsages: []x509.ExtKeyUsage{purpose}}

  if len(chain) > 0 {
    var chainCerts []*x509.Certificate
    certChain := loadPemChain(chain)
    for _, cert := range certChain.Certificate {
      x509Cert, err := x509.ParseCertificate(cert)
      if err != nil {
        panic(err)
      }
      chainCerts = append(chainCerts, x509Cert)
    }

    if len(chainCerts) > 0 {
      var rootCert *x509.Certificate = chainCerts[len(chainCerts)-1]
      opts.Roots.AddCert(rootCert)

      var intCA *x509.Certificate
      for i := 1; i < len(chainCerts)-1; i = i + 1 {
        intCA = chainCerts[i]
        opts.Intermediates.AddCert(intCA)
      }
    }
  }

  _, err = cert.Verify(opts)
  if err != nil {
    fmt.Printf("Go: Verify error: %s\n", err)
  } else {
    fmt.Printf("Go: Certificate verification succeeded (good!).\n")
  }
}
