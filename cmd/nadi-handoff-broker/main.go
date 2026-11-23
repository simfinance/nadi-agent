package main

import (
	"flag"
	"fmt"
	"os"

	"nadi-agent/internal/handoffbroker"
)

func main() {
	configPath := flag.String("config", "/etc/nadi-agent/bridge-mappings.json", "Root-owned Bridge application mapping file")
	socketPath := flag.String("socket", "/run/nadi-agent/credential-handoff.sock", "Fixed local handoff Unix socket")
	flag.Parse()

	config, err := handoffbroker.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NADI handoff broker configuration error: %v\n", err)
		os.Exit(1)
	}

	server, err := handoffbroker.NewServer(*socketPath, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NADI handoff broker initialization error: %v\n", err)
		os.Exit(1)
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "NADI handoff broker stopped: %v\n", err)
		os.Exit(1)
	}
}
