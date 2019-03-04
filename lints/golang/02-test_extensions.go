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

  if len(cert.UnhandledCriticalExtensions) > 0 {
    fmt.Printf("Go: Found unhandled critical extensions:\n")
    for _, ext := range cert.UnhandledCriticalExtensions {
      fmt.Printf("    Extension OID: %s\n", ext.String());
     }
  } else {
    fmt.Printf("Go: No unhandled critical extensions (good!).\n")
  }
}
