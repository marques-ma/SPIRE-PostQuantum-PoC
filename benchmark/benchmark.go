package main

import (
	"fmt"
	"os"

	oqsopenssl "github.com/marques-ma/pq-openssl-3.x"
)

func main() {

	// Validate command-line arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: benchmark <algorithm> <output_file>")
		os.Exit(1)
	}

	algorithm := os.Args[1]  
	outputFile := os.Args[2] 

	// Start the container
	err := oqsopenssl.StartOQSContainer()
	if err != nil {
		fmt.Println("Error starting OQS container:", err)
		return
	}
	defer oqsopenssl.StopOQSContainer()

	// Run the benchmark
	err = oqsopenssl.BenchmarkAlgorithm(algorithm, outputFile, 30) // Duration is hardcoded to 10 seconds
	if err != nil {
		fmt.Println("Error benchmarking algorithm:", err)
		return
	}

	fmt.Printf("Benchmarking completed for algorithm %s. Results saved to %s\n", algorithm, outputFile)

}