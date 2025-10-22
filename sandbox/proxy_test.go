package sandbox

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkProxy_StartStop(t *testing.T) {
	t.Parallel()

	proxy, err := NewNetworkProxy(nil)
	require.NoError(t, err)
	require.NotNil(t, proxy)

	// Verify addresses are populated
	assert.NotEmpty(t, proxy.HTTPAddr())
	assert.NotEmpty(t, proxy.SOCKSAddr())

	// Verify platform-specific address formats
	if runtime.GOOS == "linux" {
		assert.True(t, strings.HasPrefix(proxy.HTTPAddr(), "unix://"))
		assert.True(t, strings.HasPrefix(proxy.SOCKSAddr(), "unix://"))
	} else {
		assert.True(t, strings.HasPrefix(proxy.HTTPAddr(), "http://127.0.0.1:"))
		assert.True(t, strings.Contains(proxy.SOCKSAddr(), "127.0.0.1:"))
	}

	// Verify environment variables
	env := proxy.Env()
	assert.NotEmpty(t, env)

	foundHTTP := false
	foundSOCKS := false
	for _, e := range env {
		if strings.HasPrefix(e, "HTTP_PROXY=") || strings.HasPrefix(e, "http_proxy=") {
			foundHTTP = true
		}
		if strings.HasPrefix(e, "ALL_PROXY=") || strings.HasPrefix(e, "all_proxy=") {
			foundSOCKS = true
		}
	}
	assert.True(t, foundHTTP, "Should have HTTP_PROXY environment variable")
	assert.True(t, foundSOCKS, "Should have ALL_PROXY environment variable")

	// Close should succeed
	err = proxy.Close()
	assert.NoError(t, err)

	// Close should be idempotent
	err = proxy.Close()
	assert.NoError(t, err)
}

func TestNetworkProxy_MultipleInstances(t *testing.T) {
	t.Parallel()

	// Should be able to create multiple proxies concurrently
	proxy1, err := NewNetworkProxy(nil)
	require.NoError(t, err)
	defer proxy1.Close()

	proxy2, err := NewNetworkProxy(nil)
	require.NoError(t, err)
	defer proxy2.Close()

	// Addresses should be different
	assert.NotEqual(t, proxy1.HTTPAddr(), proxy2.HTTPAddr())
	assert.NotEqual(t, proxy1.SOCKSAddr(), proxy2.SOCKSAddr())
}

func TestNetworkProxy_HTTPConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	// Only test on macOS for now (TCP sockets are easier to test)
	if runtime.GOOS != "darwin" {
		t.Skip("TCP proxy test only runs on macOS")
	}

	t.Parallel()

	// Create a test HTTP server
	testServer := &testHTTPServer{}
	testServer.Start(t)
	defer testServer.Stop()

	// Create proxy with no filter (allow all)
	proxy, err := NewNetworkProxy(nil)
	require.NoError(t, err)
	defer proxy.Close()

	// Extract proxy URL (should be http://127.0.0.1:PORT on macOS)
	proxyURL, err := url.Parse(proxy.HTTPAddr())
	require.NoError(t, err)

	// Create HTTP client with proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make an HTTP request through the proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	// Verify we can read the response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "test response")
}

// Test helpers

// testHTTPServer is a simple HTTP server for testing proxy functionality.
type testHTTPServer struct {
	server *httptest.Server
	URL    string
}

func (s *testHTTPServer) Start(t *testing.T) {
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response from " + r.URL.Path))
	}))
	s.URL = s.server.URL
}

func (s *testHTTPServer) Stop() {
	if s.server != nil {
		s.server.Close()
	}
}
