package traefik_edgeone_ip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var (
	ErrMissingCredentials = errors.New("missing EdgeOne credentials: secretID and secretKey are required")
)

// Config the plugin configuration.
type Config struct {
	// Tencent Cloud API credentials.
	SecretID  string `json:"secretID,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`

	// Tencent Cloud API endpoint, default: teo.tencentcloudapi.com
	APIEndpoint string `json:"apiEndpoint,omitempty"`

	// API request timeout, e.g. "5s". Default: "5s".
	Timeout string `json:"timeout,omitempty"`

	// Cache TTL for IP validation results, e.g. "1h". Default: "1h".
	CacheTTL string `json:"cacheTTL,omitempty"`

	// LRU cache max entries. Default: 1000.
	CacheSize int `json:"cacheSize,omitempty"`

	// Log level: debug|info|warn|error. Default: info.
	LogLevel string `json:"logLevel,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		APIEndpoint: "teo.tencentcloudapi.com",
		Timeout:     "5s",
		CacheTTL:    "1h",
		CacheSize:   1000,
		LogLevel:    LogLevelInfo,
	}
}

// EdgeOneIP middleware plugin.
type EdgeOneIP struct {
	next   http.Handler
	name   string
	logger *PluginLogger

	validator EdgeOneIPValidator
	cache     *lruCache
}

// New created a new EdgeOneIP plugin.
func New(
	_ context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	if config.SecretID == "" || config.SecretKey == "" {
		return nil, ErrMissingCredentials
	}

	logger := NewPluginLogger(name, config.LogLevel)

	cacheTTL, err := parseDurationWithDefault(config.CacheTTL, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("invalid cacheTTL: %w", err)
	}
	timeout, err := parseDurationWithDefault(config.Timeout, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	cache := newLRUCache(config.CacheSize, cacheTTL)

	timeoutSeconds := durationToTimeoutSeconds(timeout.Seconds())
	validator, err := newTencentEdgeOneIPValidator(config.SecretID, config.SecretKey, config.APIEndpoint, timeoutSeconds)
	if err != nil {
		return nil, err
	}

	return &EdgeOneIP{
		next:      next,
		name:      name,
		logger:    logger,
		validator: validator,
		cache:     cache,
	}, nil
}

func parseDurationWithDefault(raw string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	return d, nil
}

func (m *EdgeOneIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			m.logger.ErrorContext(req.Context(), "panic recovered")
			m.next.ServeHTTP(rw, req)
		}
	}()

	ctx := req.Context()

	srcIP, err := parseRemoteAddrIP(req.RemoteAddr)
	if err != nil {
		m.logger.WarnContext(ctx, "failed to parse source IP", "remoteAddr", req.RemoteAddr, "err", err)
		m.next.ServeHTTP(rw, req)
		return
	}

	isEdgeOne, err := m.validateEdgeOneIP(ctx, srcIP)
	if err != nil {
		m.logger.ErrorContext(ctx, "edgeone ip validation failed, treating as untrusted", "src_ip", srcIP.String(), "err", err)
		isEdgeOne = false
	}

	realIP := srcIP
	if isEdgeOne {
		realIP = m.resolveRealIP(req, srcIP)
	}

	req.Header.Set(HeaderXRealIP, realIP.String())
	if isEdgeOne {
		req.Header.Set(HeaderXIsTrusted, "yes")
		m.prependXForwardedFor(req, realIP)
	} else {
		req.Header.Set(HeaderXIsTrusted, "no")
		req.Header.Set(HeaderXForwardedFor, srcIP.String())
	}

	m.next.ServeHTTP(rw, req)
}

func (m *EdgeOneIP) validateEdgeOneIP(ctx context.Context, ip netip.Addr) (bool, error) {
	// Private/local/link-local source IPs can never be EdgeOne nodes.
	// Short-circuit to avoid unnecessary API calls.
	if isPrivateIP(ip) {
		return false, nil
	}

	key := ip.String()
	if cached, ok := m.cache.Get(key); ok {
		return cached, nil
	}

	valid, err := m.validator.Validate(ctx, ip)
	if err != nil {
		return false, err
	}

	m.cache.Add(key, valid)
	return valid, nil
}

func parseRemoteAddrIP(remoteAddr string) (netip.Addr, error) {
	// Best-effort: usually "IP:port". If SplitHostPort fails, try parsing as plain IP.
	host := remoteAddr

	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip, nil
}

func (m *EdgeOneIP) resolveRealIP(req *http.Request, srcIP netip.Addr) netip.Addr {
	if ip, ok := parseSingleIPHeader(req, HeaderEoConnectingIP); ok {
		return ip
	}

	if ip, ok := parseSingleIPHeader(req, HeaderXRealIP); ok && !isPrivateIP(ip) {
		return ip
	}

	if ip, ok := parseXForwardedFor(req); ok {
		return ip
	}

	return srcIP
}

func parseSingleIPHeader(req *http.Request, header string) (netip.Addr, bool) {
	values := req.Header.Values(header)
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	val := strings.TrimSpace(values[0])
	if val == "" {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(val)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

func parseXForwardedFor(req *http.Request) (netip.Addr, bool) {
	values := req.Header.Values(HeaderXForwardedFor)
	if len(values) != 1 {
		return netip.Addr{}, false
	}

	parts := strings.Split(values[0], ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			continue
		}
		if isPrivateIP(ip) {
			continue
		}
		return ip, true
	}

	return netip.Addr{}, false
}

func isPrivateIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
}

func (m *EdgeOneIP) prependXForwardedFor(req *http.Request, ip netip.Addr) {
	if req.Header.Get(HeaderXForwardedFor) == "" {
		req.Header.Set(HeaderXForwardedFor, ip.String())
		return
	}

	newVals := make([]string, 0, 4)
	newVals = append(newVals, ip.String())

	//nolint:modernize // keep it simple/compatible for Traefik plugin runtime.
	vals := strings.Split(req.Header.Get(HeaderXForwardedFor), ",")
	for _, val := range vals {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if val == ip.String() {
			continue
		}
		newVals = append(newVals, val)
	}

	req.Header.Set(HeaderXForwardedFor, strings.Join(newVals, ", "))
}
