package traefik_edgeone_ip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
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

func expandConfig(config *Config) *Config {
	return &Config{
		SecretID:    os.ExpandEnv(config.SecretID),
		SecretKey:   os.ExpandEnv(config.SecretKey),
		APIEndpoint: os.ExpandEnv(config.APIEndpoint),
		Timeout:     os.ExpandEnv(config.Timeout),
		CacheTTL:    os.ExpandEnv(config.CacheTTL),
	}
}

// EdgeOneIP middleware plugin.
type EdgeOneIP struct {
	next   http.Handler
	name   string
	logger *PluginLogger

	validator EdgeOneIPValidator
	cache     *lru.LRU[string, bool]
	sg        singleflight.Group
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
	config = expandConfig(config)
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

	cache := lru.NewLRU[string, bool](config.CacheSize, nil, cacheTTL)

	timeoutSeconds := durationToTimeoutSeconds(timeout.Seconds())
	validator, err := newTencentEdgeOneIPValidator(
		config.SecretID,
		config.SecretKey,
		config.APIEndpoint,
		timeoutSeconds)
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
	ipStr := srcIP.String()

	isEdgeOne := false
	if cached, ok := m.cache.Get(ipStr); ok {
		isEdgeOne = cached
	} else if srcIP.IsPrivate() || srcIP.IsLoopback() || srcIP.IsLinkLocalMulticast() || srcIP.IsLinkLocalUnicast() {
		isEdgeOne = false
	} else {
		valid, err, _ := m.sg.Do(ipStr, func() (any, error) {
			return m.validator.Validate(ctx, srcIP)
		})
		if err != nil {
			m.logger.ErrorContext(ctx, "validateEdgeOneIP failed", "ip", ipStr, "error", err)
			isEdgeOne = false
		} else {
			isEdgeOne = valid.(bool)
			m.cache.Add(ipStr, isEdgeOne)
		}
	}

	xff := make([]string, 0, 10) // set capacity to 10 to avoid unnecessary allocations
	for _, header := range req.Header.Values(HeaderXForwardedFor) {
		for val := range strings.SplitSeq(strings.TrimSpace(header), ",") {
			if ip, err := netip.ParseAddr(strings.TrimSpace(val)); err == nil {
				xff = append(xff, ip.String())
			}
		}
	}
	xff = append(xff, ipStr)

	if isEdgeOne {
		req.Header.Set(HeaderXForwardedFromEdgeOne, "yes")
		req.Header.Set(HeaderXForwardedFor, strings.Join(xff, ", "))
		req.Header.Set(HeaderXRealIP, xff[0])
	} else {
		req.Header.Set(HeaderXForwardedFromEdgeOne, "no")
		req.Header.Set(HeaderXForwardedFor, ipStr)
		req.Header.Set(HeaderXRealIP, ipStr)
	}

	m.next.ServeHTTP(rw, req)
}

func parseRemoteAddrIP(remoteAddr string) (*netip.Addr, error) {
	var ip netip.Addr
	var err error
	switch strings.Count(remoteAddr, ":") {
	case 0: // Plain IPv4 address
		ip, err = netip.ParseAddr(remoteAddr)
	case 1: // IPv4 address with port
		ip, err = netip.ParseAddr(remoteAddr[:strings.LastIndex(remoteAddr, ":")])
	default: // IPv6 address, might have port
		if strings.HasPrefix(remoteAddr, "[") {
			remoteAddr = remoteAddr[1:strings.LastIndex(remoteAddr, "]")]
		}
		ip, err = netip.ParseAddr(remoteAddr)
	}
	if err != nil {
		return nil, err
	}
	return &ip, nil
}
