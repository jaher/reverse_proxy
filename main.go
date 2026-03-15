package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

type filterFlags []string

func (f *filterFlags) String() string { return fmt.Sprintf("%v", *f) }
func (f *filterFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	port := flag.Int("port", 0, "Port to listen on (0 for random available port)")
	mitm := flag.Bool("mitm", false, "Enable TLS MITM interception (generates CA cert on first run)")
	caCertPath := flag.String("ca-cert", "ca.pem", "Path to CA certificate file")
	caKeyPath := flag.String("ca-key", "ca-key.pem", "Path to CA private key file")
	dbPath := flag.String("db", "", "Path to SQLite database for capturing traffic (e.g. capture.db)")
	var filters filterFlags
	flag.Var(&filters, "filter", "Intercept filter as field:regex (repeatable). Fields: host, url, method, content-type, body, header")
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

	var db *DB
	if *dbPath != "" {
		var err error
		db, err = OpenDB(*dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()
		cfg.DB = db
		fmt.Fprintf(os.Stderr, "Database capture enabled: %s\n", *dbPath)
	}

	interceptor := NewInterceptor()

	// Load CLI filters
	for _, spec := range filters {
		field, pattern, err := ParseFilterSpec(spec)
		if err != nil {
			log.Fatalf("Invalid filter %q: %v", spec, err)
		}
		if err := interceptor.AddFilter(field, pattern); err != nil {
			log.Fatalf("Invalid filter regex %q: %v", spec, err)
		}
		fmt.Fprintf(os.Stderr, "Intercept filter: %s =~ /%s/\n", field, pattern)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	listenAddr := listener.Addr().String()
	store := NewConnectionStore()
	ui := NewUI(store, listenAddr, db, interceptor)

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
