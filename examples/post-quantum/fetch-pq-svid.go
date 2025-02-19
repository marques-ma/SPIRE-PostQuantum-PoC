package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func main() {

	// Set the SPIFFE workload API socket address
	err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
	if err != nil {
		log.Fatalf("Error setting SPIFFE_ENDPOINT_SOCKET: %v", err)
	}

	// Fetch SVID from SPIRE Workload API
	svid, err := fetchSVID()
	if err != nil {
		log.Fatalf("Error fetching SVID: %v", err)
	}

	// Retrieve the leaf certificate
	leafCert := svid.Certificates[0]
	if len(leafCert.DNSNames) == 0 {
		log.Fatalf("No DNSNames found in the SVID certificate")
	}

	// In the POC, the crypto material is injected in workload cert (last position in DNSNames field) as privateKey||certificate. it.
	concatenatedString := leafCert.DNSNames[len(leafCert.DNSNames)-1]

	// retrieve the private key and certificate
	result := strings.SplitAfter(concatenatedString, "-----END PRIVATE KEY-----")
	fmt.Println("Private key:\n", result[0])
	fmt.Println("Cert:\n", result[1])
}

func fetchSVID() (*x509svid.SVID, error) {

	// Fetch the X509SVID containing the crypto material (i.e., private key and cert)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	x509SVID, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	return x509SVID, nil
}
