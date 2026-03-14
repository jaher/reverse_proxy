package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	port := flag.Int("port", 0, "Port to listen on (0 for random available port)")
	mitm := flag.Bool("mitm", false, "Enable TLS MITM interception (generates CA cert on first run)")
	caCertPath := flag.String("ca-cert", "ca.pem", "Path to CA certificate file")
	caKeyPath := flag.String("ca-key", "ca-key.pem", "Path to CA private key file")
	flag.Parse()

	var cfg ProxyConfig

	if *mitm {
		ca, caKey, err := LoadOrCreateCA(*caCertPath, *caKeyPath)
		if err != nil {
			log.Fatalf("Failed to load/create CA: %v", err)
		}
		cfg.CertCache = NewCertCache(ca, caKey)
		cfg.MITMEnabled = true
		fmt.Fprintf(os.Stderr, "TLS MITM enabled. Trust the CA certificate: %s\n", *caCertPath)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()
	store := NewConnectionStore()
	ui := NewUI(store, listenAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn, ui, &cfg)
		}
	}()

	if err := ui.App.Run(); err != nil {
		log.Fatalf("TUI error: %v", err)
	}
}
