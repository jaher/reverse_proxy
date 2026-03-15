package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socksVersion = 0x05

	authNone = 0x00

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess              = 0x00
	replyConnectionRefused    = 0x05
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08

	ipv4Len = 4
	ipv6Len = 16

	tlsHandshakeType = 0x16
)

type ProxyConfig struct {
	CertCache   *CertCache
	MITMEnabled bool
	DB          *DB
}

type CaptureWriter struct {
	conn      *Connection
	direction string // "c2s" or "s2c"
	dest      io.Writer
	onWrite   func()
}

func (cw *CaptureWriter) Write(p []byte) (int, error) {
	n, err := cw.dest.Write(p)
	if n > 0 {
		cw.conn.mu.Lock()
		switch cw.direction {
		case "c2s":
			if cw.conn.ClientToServer.Len() < maxCaptureSize {
				cw.conn.ClientToServer.Write(p[:n])
			}
		case "s2c":
			if cw.conn.ServerToClient.Len() < maxCaptureSize {
				cw.conn.ServerToClient.Write(p[:n])
			}
		}
		cw.conn.mu.Unlock()
		cw.onWrite()
	}
	return n, err
}

// bufferedConn wraps a net.Conn with a bufio.Reader so peeked bytes aren't lost
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

func handleConnection(client net.Conn, ui *UI, cfg *ProxyConfig) {
	defer client.Close()

	clientAddr := client.RemoteAddr().String()

	// SOCKS5 greeting
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil {
		return
	}
	if buf[0] != socksVersion {
		return
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	if _, err := client.Write([]byte{socksVersion, authNone}); err != nil {
		return
	}

	// SOCKS5 request
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[0] != socksVersion {
		return
	}
	if header[1] != cmdConnect {
		sendReply(client, replyCommandNotSupported)
		return
	}

	var destAddr string

	switch header[3] {
	case atypIPv4:
		ipBuf := make([]byte, ipv4Len)
		if _, err := io.ReadFull(client, ipBuf); err != nil {
			return
		}
		destAddr = net.IP(ipBuf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(client, domainBuf); err != nil {
			return
		}
		destAddr = string(domainBuf)

	case atypIPv6:
		ipBuf := make([]byte, ipv6Len)
		if _, err := io.ReadFull(client, ipBuf); err != nil {
			return
		}
		destAddr = net.IP(ipBuf).String()

	default:
		sendReply(client, replyAddrTypeNotSupported)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	destPort := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(destAddr, strconv.Itoa(int(destPort)))

	// Register connection
	connRecord := ui.Store.Add(target, clientAddr)
	ui.RefreshList()

	// Connect to destination
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendReply(client, replyConnectionRefused)
		connRecord.mu.Lock()
		connRecord.Status = "FAILED"
		connRecord.mu.Unlock()
		ui.RefreshList()
		return
	}
	defer remote.Close()

	// Send SOCKS5 success
	localAddr := remote.LocalAddr().(*net.TCPAddr)
	reply := make([]byte, 10)
	reply[0] = socksVersion
	reply[1] = replySuccess
	reply[2] = 0x00
	reply[3] = atypIPv4
	copy(reply[4:8], localAddr.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(localAddr.Port))
	if _, err := client.Write(reply); err != nil {
		return
	}

	// Peek at the first byte to detect TLS
	var clientReader io.Reader = client
	var clientWriter io.Writer = client
	var remoteReader io.Reader = remote
	var remoteWriter io.Writer = remote

	if cfg.MITMEnabled && cfg.CertCache != nil {
		br := bufio.NewReader(client)
		firstByte, err := br.Peek(1)
		if err == nil && len(firstByte) > 0 && firstByte[0] == tlsHandshakeType {
			// TLS detected — do MITM
			connRecord.mu.Lock()
			connRecord.TLSIntercepted = true
			connRecord.mu.Unlock()

			cert, err := cfg.CertCache.GetCertificate(destAddr)
			if err != nil {
				log.Printf("Failed to get cert for %s: %v", destAddr, err)
				// Fall through to raw relay
			} else {
				// Wrap client side with TLS server
				tlsClient := tls.Server(&bufferedConn{r: br, Conn: client}, &tls.Config{
					Certificates: []tls.Certificate{*cert},
				})
				if err := tlsClient.Handshake(); err != nil {
					// Client rejected our cert, fall through to raw relay
					connRecord.mu.Lock()
					connRecord.TLSIntercepted = false
					connRecord.Status = "CLOSED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				defer tlsClient.Close()

				// Wrap remote side with TLS client
				tlsRemote := tls.Client(remote, &tls.Config{
					ServerName: destAddr,
				})
				if err := tlsRemote.Handshake(); err != nil {
					connRecord.mu.Lock()
					connRecord.Status = "FAILED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				defer tlsRemote.Close()

				clientReader = tlsClient
				clientWriter = tlsClient
				remoteReader = tlsRemote
				remoteWriter = tlsRemote
				ui.RefreshList()

				goto relay
			}
		}

		// Not TLS or cert error — use buffered reader so peeked byte isn't lost
		clientReader = &bufferedConn{r: br, Conn: client}
	}

relay:
	refreshFn := func() { ui.RefreshList() }
	c2s := &CaptureWriter{conn: connRecord, direction: "c2s", dest: remoteWriter, onWrite: refreshFn}
	s2c := &CaptureWriter{conn: connRecord, direction: "s2c", dest: clientWriter, onWrite: refreshFn}

	// Intercept the first c2s chunk if intercept is enabled
	if ui.Interceptor.IsEnabled() {
		firstBuf := make([]byte, 65536)
		n, readErr := clientReader.Read(firstBuf)
		if n > 0 {
			result := ui.Interceptor.ProcessFilters(connRecord, firstBuf[:n])

			if !result.Matched {
				// No filter matched — forward without pausing
				if _, err := c2s.Write(firstBuf[:n]); err != nil {
					connRecord.mu.Lock()
					connRecord.Status = "FAILED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				if readErr != nil {
					connRecord.mu.Lock()
					connRecord.Status = "CLOSED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				goto startRelay
			}

			if result.Rewritten {
				// Awk rewrite filter produced replacement data — auto-forward
				if _, err := c2s.Write(result.RewriteData); err != nil {
					connRecord.mu.Lock()
					connRecord.Status = "FAILED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				if readErr != nil {
					connRecord.mu.Lock()
					connRecord.Status = "CLOSED"
					connRecord.mu.Unlock()
					ui.RefreshList()
					return
				}
				goto startRelay
			}

			// Match without rewrite — pause for manual editing
			data, forward := ui.Interceptor.Submit(connRecord, firstBuf[:n])
			if !forward {
				connRecord.mu.Lock()
				connRecord.Status = "DROPPED"
				connRecord.mu.Unlock()
				ui.RefreshList()
				return
			}
			if _, err := c2s.Write(data); err != nil {
				connRecord.mu.Lock()
				connRecord.Status = "FAILED"
				connRecord.mu.Unlock()
				ui.RefreshList()
				return
			}
		}
		if readErr != nil {
			connRecord.mu.Lock()
			connRecord.Status = "CLOSED"
			connRecord.mu.Unlock()
			ui.RefreshList()
			return
		}
	}

startRelay:
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(c2s, clientReader)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(s2c, remoteReader)
		done <- struct{}{}
	}()

	<-done

	connRecord.mu.Lock()
	connRecord.Status = "CLOSED"
	connRecord.mu.Unlock()

	// Save to database if enabled
	if cfg.DB != nil {
		cfg.DB.SaveConnection(connRecord)
	}

	ui.RefreshList()
}

func sendReply(client net.Conn, status byte) {
	reply := []byte{socksVersion, status, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	client.Write(reply)
}
