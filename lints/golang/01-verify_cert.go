package main

import (
  "os"
  "fmt"
  "io/ioutil"
  "log"
  "crypto/x509"
  "encoding/pem"
)

func main() {
  // Read and parse the PEM certificate file
  if len(os.Args) < 2 {
    fmt.Println("Usage: script.go <cert>")
    return
  }

  file := os.Args[1]
  //chain := os.Args[2]

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

  _, err = cert.Verify(opts)
  if err != nil {
    fmt.Printf("Go: Verify error: %s\n", err)
  } else {
    fmt.Printf("Go: Certificate verification succeeded (good!).\n")
  }
}
