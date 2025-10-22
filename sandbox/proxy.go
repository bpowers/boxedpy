package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// NetworkFilter specifies allowed and denied network destinations for proxy filtering.
// Patterns support wildcards (e.g., "*.github.com" matches "api.github.com" but not "github.com").
// Deny rules take precedence over allow rules.
// If AllowHosts is empty, all destinations are allowed (unless explicitly denied).
// If AllowHosts is non-empty, only matching destinations are allowed.
type NetworkFilter struct {
	// AllowHosts contains patterns for allowed destinations.
	// Examples: "github.com", "*.npmjs.org", "example.com:443"
	AllowHosts []string

	// DenyHosts contains patterns for denied destinations.
	// Deny takes precedence over allow.
	DenyHosts []string
}

// NetworkProxy manages HTTP and SOCKS5 proxy servers with optional domain filtering.
// On macOS, proxies listen on localhost TCP sockets with OS-allocated ports.
// On Linux, proxies listen on Unix domain sockets in a temporary directory.
//
// The proxy must be explicitly closed via Close() to clean up resources.
// Goroutine leaks will occur if Close() is not called.
//
// Example usage:
//
//	filter := &NetworkFilter{
//	    AllowHosts: []string{"github.com", "*.npmjs.org"},
//	}
//	proxy, err := NewNetworkProxy(filter)
//	if err != nil {
//	    return err
//	}
//	defer proxy.Close()
//
//	// Use proxy.Env() to configure sandboxed processes
//	policy.NetworkProxy = proxy
type NetworkProxy struct {
	filter      *NetworkFilter
	httpAddr    string
	socksAddr   string
	httpLn      net.Listener
	socksLn     net.Listener
	socksTmpDir string // For Unix socket cleanup on Linux
	closeOnce   sync.Once
	closed      chan struct{}
	wg          sync.WaitGroup

	mu         sync.Mutex
	httpServer *http.Server
}

// NewNetworkProxy creates and starts HTTP and SOCKS5 proxy servers with the given filter.
// The proxies begin accepting connections immediately.
// The returned proxy must be closed via Close() to prevent resource leaks.
func NewNetworkProxy(filter *NetworkFilter) (*NetworkProxy, error) {
	httpLn, socksLn, tmpDir, err := createListeners()
	if err != nil {
		return nil, fmt.Errorf("create listeners: %w", err)
	}

	p := &NetworkProxy{
		filter:      filter,
		httpLn:      httpLn,
		socksLn:     socksLn,
		socksTmpDir: tmpDir,
		closed:      make(chan struct{}),
	}

	// Get listener addresses
	p.httpAddr = formatAddress(httpLn.Addr())
	p.socksAddr = formatAddress(socksLn.Addr())

	// Start HTTP proxy server
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx := context.Background()
		if err := p.serveHTTP(ctx); err != nil {
			// Shutdown errors are expected, ignore them
		}
	}()

	// Start SOCKS5 proxy server
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx := context.Background()
		if err := p.serveSOCKS(ctx); err != nil {
			// Shutdown errors are expected, ignore them
		}
	}()

	return p, nil
}

// HTTPAddr returns the HTTP proxy address in a format suitable for HTTP_PROXY environment variables.
// On macOS: "http://127.0.0.1:PORT"
// On Linux: "unix:///path/to/http.sock"
func (p *NetworkProxy) HTTPAddr() string {
	return p.httpAddr
}

// SOCKSAddr returns the SOCKS5 proxy address.
// On macOS: "127.0.0.1:PORT"
// On Linux: "unix:///path/to/socks.sock"
func (p *NetworkProxy) SOCKSAddr() string {
	return p.socksAddr
}

// Env returns environment variables configuring HTTP and SOCKS5 proxies.
// Includes both uppercase and lowercase variants for maximum compatibility.
// The caller should append these to cmd.Env when executing sandboxed commands.
func (p *NetworkProxy) Env() []string {
	httpAddr := p.HTTPAddr()
	socksAddr := p.SOCKSAddr()

	env := []string{
		"HTTP_PROXY=" + httpAddr,
		"HTTPS_PROXY=" + httpAddr,
		"http_proxy=" + httpAddr,
		"https_proxy=" + httpAddr,
	}

	// SOCKS proxy format differs between platforms
	if runtime.GOOS == "linux" {
		// Unix socket format for socks
		env = append(env,
			"ALL_PROXY="+socksAddr,
			"all_proxy="+socksAddr,
		)
	} else {
		// TCP socket format for socks (socks5://host:port)
		env = append(env,
			"ALL_PROXY=socks5://"+socksAddr,
			"all_proxy=socks5://"+socksAddr,
		)
	}

	return env
}

// Close gracefully shuts down the proxy servers and cleans up resources.
// It waits for all active connections to complete before returning.
// Close is safe to call multiple times (idempotent).
func (p *NetworkProxy) Close() error {
	var closeErr error

	p.closeOnce.Do(func() {
		// Signal shutdown to all goroutines
		close(p.closed)

		// Stop accepting new connections
		if p.httpLn != nil {
			p.httpLn.Close()
		}
		if p.socksLn != nil {
			p.socksLn.Close()
		}

		// Gracefully shutdown HTTP server
		p.mu.Lock()
		httpServer := p.httpServer
		p.mu.Unlock()

		if httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			httpServer.Shutdown(ctx)
		}

		// Wait for all connection handlers to finish
		p.wg.Wait()

		// Clean up Unix sockets on Linux
		if p.socksTmpDir != "" {
			if err := os.RemoveAll(p.socksTmpDir); err != nil {
				closeErr = fmt.Errorf("cleanup sockets directory: %w", err)
			}
		}
	})

	return closeErr
}

// serveHTTP runs the HTTP proxy server. It blocks until the listener is closed.
func (p *NetworkProxy) serveHTTP(ctx context.Context) error {
	handler := http.HandlerFunc(p.handleHTTPRequest)
	server := &http.Server{Handler: handler}

	p.mu.Lock()
	p.httpServer = server
	p.mu.Unlock()

	err := server.Serve(p.httpLn)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// serveSOCKS runs the SOCKS5 proxy server. It blocks until the listener is closed.
func (p *NetworkProxy) serveSOCKS(ctx context.Context) error {
	for {
		conn, err := p.socksLn.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return nil
			default:
				// Temporary error, continue accepting
				continue
			}
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleSOCKS(conn)
		}()
	}
}

// handleHTTPRequest processes HTTP proxy requests (GET, POST, CONNECT, etc.).
func (p *NetworkProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// For non-CONNECT requests (regular HTTP proxy), we use a reverse proxy approach
	// This handles GET, POST, etc. requests properly
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	if host == "" {
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	// Extract host and port
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		// No port specified, assume default based on scheme
		hostname = host
		if r.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Check filter
	if !p.isAllowed(hostname, port) {
		http.Error(w, "Forbidden: destination not allowed", http.StatusForbidden)
		return
	}

	// Create HTTP client to forward the request
	targetURL := r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}

	// Create a new request to the target
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

// handleConnect handles HTTP CONNECT requests for HTTPS tunneling.
func (p *NetworkProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract target host:port from request
	targetAddr := r.Host
	if targetAddr == "" {
		targetAddr = r.URL.Host
	}

	if targetAddr == "" {
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	// Parse host and port
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		// CONNECT requires explicit port
		http.Error(w, "Bad Request: invalid host:port", http.StatusBadRequest)
		return
	}

	// Check filter
	if !p.isAllowed(host, port) {
		http.Error(w, "Forbidden: destination not allowed", http.StatusForbidden)
		return
	}

	// Dial target
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Internal Server Error: hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send success response to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Start bidirectional copy
	bidirectionalCopy(targetConn, clientConn)
}

// isAllowed checks if a connection to the given host and port is allowed by the filter.
func (p *NetworkProxy) isAllowed(host, port string) bool {
	if p.filter == nil {
		return true
	}

	// Placeholder - full implementation in Phase 4
	// For now, allow everything if filter is set but empty
	if len(p.filter.AllowHosts) == 0 && len(p.filter.DenyHosts) == 0 {
		return true
	}

	// Temporary: allow all if filter exists (will be properly implemented in Phase 4)
	return true
}

// handleSOCKS processes a SOCKS5 connection.
func (p *NetworkProxy) handleSOCKS(clientConn net.Conn) error {
	defer clientConn.Close()
	// Placeholder - will be implemented in Phase 3
	return nil
}

// Platform-specific listener creation

// createListeners creates HTTP and SOCKS5 listeners appropriate for the platform.
// Returns (httpListener, socksListener, tmpDir, error).
// On Linux, tmpDir contains the Unix socket files and must be cleaned up.
// On macOS, tmpDir is empty.
func createListeners() (httpLn, socksLn net.Listener, tmpDir string, err error) {
	if runtime.GOOS == "linux" {
		return createUnixListeners()
	}
	return createTCPListeners()
}

// createUnixListeners creates Unix domain socket listeners for Linux.
func createUnixListeners() (httpLn, socksLn net.Listener, tmpDir string, err error) {
	tmpDir, err = os.MkdirTemp("", "boxedpy-proxy-*")
	if err != nil {
		return nil, nil, "", fmt.Errorf("create temp dir: %w", err)
	}

	httpSock := filepath.Join(tmpDir, "http.sock")
	socksSock := filepath.Join(tmpDir, "socks.sock")

	// Remove stale sockets if they exist
	os.Remove(httpSock)
	os.Remove(socksSock)

	httpLn, err = net.Listen("unix", httpSock)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, "", fmt.Errorf("listen on unix socket %s: %w", httpSock, err)
	}

	socksLn, err = net.Listen("unix", socksSock)
	if err != nil {
		httpLn.Close()
		os.RemoveAll(tmpDir)
		return nil, nil, "", fmt.Errorf("listen on unix socket %s: %w", socksSock, err)
	}

	return httpLn, socksLn, tmpDir, nil
}

// createTCPListeners creates TCP listeners on localhost for macOS.
func createTCPListeners() (httpLn, socksLn net.Listener, tmpDir string, err error) {
	httpLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, "", fmt.Errorf("listen on tcp: %w", err)
	}

	socksLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		httpLn.Close()
		return nil, nil, "", fmt.Errorf("listen on tcp: %w", err)
	}

	return httpLn, socksLn, "", nil
}

// formatAddress converts a net.Addr to the appropriate proxy URL format.
func formatAddress(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		// TCP address on macOS: "http://127.0.0.1:PORT"
		return fmt.Sprintf("http://%s", a.String())
	case *net.UnixAddr:
		// Unix socket on Linux: "unix:///path/to/socket"
		return fmt.Sprintf("unix://%s", a.Name)
	default:
		return addr.String()
	}
}

// bidirectionalCopy copies data bidirectionally between two connections.
// It closes both connections when either direction finishes or encounters an error.
func bidirectionalCopy(dst, src net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// Close write side to signal EOF to peer
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}

	go copy(dst, src)
	go copy(src, dst)

	wg.Wait()

	dst.Close()
	src.Close()
}
