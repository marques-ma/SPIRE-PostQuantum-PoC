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

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

// SVID represents a structure holding the SPIFFE ID and certificate data.
type SVID struct {
	ID          string
	Certificates []*x509.Certificate
}

// fetchSVID fetches the SVID from SPIRE (this function should be implemented based on your setup).
func fetchSVID() (*SVID, error) {
	// Implement SPIRE Workload API client call to retrieve SVID
	// Example placeholder
	return &SVID{
		ID: "spiffe://example.org/workload",
		Certificates: []*x509.Certificate{}, // Replace with actual SVID certificates
	}, nil
}

func main() {
	// Set SPIFFE workload API socket address
	err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
	if err != nil {
		log.Fatalf("Error setting SPIFFE_ENDPOINT_SOCKET: %v", err)
	}

	// Fetch SVID from SPIRE Workload API
	svid, err := fetchSVID()
	if err != nil {
		log.Fatalf("Error fetching SVID: %v", err)
	}

	// Print SPIFFE ID
	fmt.Println("SPIFFE ID:", svid.ID)

	// Ensure there is at least one certificate
	if len(svid.Certificates) == 0 {
		log.Fatal("No SVID certificates found")
	}

	// Extract the leaf certificate (first in the chain)
	leafCert := svid.Certificates[0]

	// Print certificate details
	fmt.Println("SVID Certificate:")
	for _, cert := range svid.Certificates {
		pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		fmt.Println(string(pemData))
	}

	// Ensure there are DNSNames in the certificate
	if len(leafCert.DNSNames) == 0 {
		log.Fatal("No DNSNames found in leaf certificate")
	}

	// Extract concatenated private key and certificate from last DNSNames field
	concatenatedString := leafCert.DNSNames[len(leafCert.DNSNames)-1]

	// Decode the private key and certificate
	result := strings.SplitAfter(concatenatedString, "-----END PRIVATE KEY-----")
	if len(result) < 2 {
		log.Fatal("Failed to split private key and certificate")
	}

	privateKey := result[0]
	cert := result[1]

	// Print extracted values
	fmt.Println("Extracted Private Key:\n", privateKey)
	fmt.Println("Extracted Certificate:\n", cert)
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
