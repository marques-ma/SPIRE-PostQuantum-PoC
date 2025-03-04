package main

import (
        "fmt"
        "os"
        "strconv"

        oqsopenssl "github.com/marques-ma/pq-openssl-3.x"
)

func main() {

        // Validate command-line arguments
        if len(os.Args) < 4 {
                fmt.Println("Usage: benchmark <algorithm> <duration_in_seconds> <output_file>")
                os.Exit(1)
        }

        algorithm := os.Args[1]
        duration, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("Error converting duration to int:", err)
		return
	}
        outputFile := os.Args[3]

        // Start the container
        err = oqsopenssl.StartOQSContainer()
        if err != nil {
                fmt.Println("Error starting OQS container:", err)
                return
        }
        defer oqsopenssl.StopOQSContainer()

        // Run the benchmark
        err = oqsopenssl.BenchmarkAlgorithm(algorithm, outputFile, duration)
        if err != nil {
                fmt.Println("Error benchmarking algorithm:", err)
                return
        }

        fmt.Printf("Benchmarking completed for algorithm %s. Results saved to %s\n", algorithm, outputFile)

}
