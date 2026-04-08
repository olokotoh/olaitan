package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collector":
		fmt.Println("olaitan collector: not yet implemented")
	case "aggregator":
		fmt.Println("olaitan aggregator: not yet implemented")
	case "version":
		fmt.Printf("olaitan %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: olaitan <command>

Commands:
  collector    Run the signal collector (DaemonSet mode)
  aggregator   Run the aggregator (correlator + decision + response)
  version      Print version
  help         Show this help

Olaitan — LLM-powered autonomous runtime security agent for Kubernetes.
`)
}
