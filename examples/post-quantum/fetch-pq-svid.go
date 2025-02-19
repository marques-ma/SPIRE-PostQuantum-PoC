package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"os"

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

	// Print the SPIFFE ID
	fmt.Println("SPIFFE ID:", svid.ID)

	// Print the certificate details
	fmt.Println("SVID Certificate:")
	for _, cert := range svid.Certificates {
		pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		fmt.Println(string(pemData))
	}
}

// fetchSVID retrieves the SVID using SPIRE's Workload API
func fetchSVID() (*x509svid.SVID, error) {
	ctx := context.Background()

	// Create a Workload API client
	client, err := workloadapi.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Workload API client: %w", err)
	}
	defer client.Close()

	// Fetch X.509 SVID context
	x509Context, err := client.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch X.509 SVID context: %w", err)
	}

	// Return the first SVID (usually there is only one)
	if len(x509Context.SVIDs) > 0 {
		return x509Context.SVIDs[0], nil
	}

	return nil, fmt.Errorf("no SVID found")
}
