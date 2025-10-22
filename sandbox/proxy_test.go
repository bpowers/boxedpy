package sandbox

import (
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
