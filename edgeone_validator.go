package traefik_edgeone_ip

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

type EdgeOneIPValidator interface {
	Validate(ctx context.Context, ip *netip.Addr) (bool, error)
}

type tencentEdgeOneIPValidator struct {
	secretID  string
	secretKey string
	endpoint  string
	client    *http.Client
}

func newTencentEdgeOneIPValidator(secretID, secretKey, apiEndpoint string, timeoutSeconds int) (*tencentEdgeOneIPValidator, error) {
	endpoint, err := normalizeTencentCloudEndpoint(apiEndpoint, "teo.tencentcloudapi.com")
	if err != nil {
		return nil, xerrors.Errorf("normalize apiEndpoint: %w", err)
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	return &tencentEdgeOneIPValidator{
		secretID:  secretID,
		secretKey: secretKey,
		endpoint:  endpoint,
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}, nil
}

func durationToTimeoutSeconds(durSeconds float64) int {
	if durSeconds <= 0 {
		return 0
	}
	return int(math.Ceil(durSeconds))
}

func (v *tencentEdgeOneIPValidator) Validate(ctx context.Context, ip *netip.Addr) (bool, error) {
	payloadBytes, err := json.Marshal(describeIPRegionRequest{
		IPs: []string{ip.String()},
	})
	if err != nil {
		return false, xerrors.Errorf("encode DescribeIPRegion request: %w", err)
	}

	respBytes, err := v.doTencentCloudJSONRequest(ctx, "teo", "2022-09-01", "DescribeIPRegion", payloadBytes)
	if err != nil {
		return false, xerrors.Errorf("DescribeIPRegion request failed: %w", err)
	}

	var resp describeIPRegionResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return false, xerrors.Errorf("decode DescribeIPRegion response: %w", err)
	}
	if resp.Response == nil {
		return false, xerrors.New("DescribeIPRegion: missing Response")
	}
	if resp.Response.Error != nil {
		return false, &tencentCloudAPIError{
			Code:      resp.Response.Error.Code,
			Message:   resp.Response.Error.Message,
			RequestID: resp.Response.RequestId,
		}
	}

	validated := len(resp.Response.IPRegionInfo) > 0 &&
		!slices.ContainsFunc(resp.Response.IPRegionInfo, func(info *ipRegionInfo) bool {
			return info == nil || info.IsEdgeOneIP != "yes" || info.IP == ""
		})
	return validated, nil
}

type describeIPRegionRequest struct {
	IPs []string `json:"IPs"`
}

type describeIPRegionResponse struct {
	Response *struct {
		IPRegionInfo []*ipRegionInfo    `json:"IPRegionInfo"`
		Error        *tencentCloudError `json:"Error,omitempty"`
		RequestId    string             `json:"RequestId"`
	} `json:"Response"`
}

type ipRegionInfo struct {
	IP          string `json:"IP"`
	IsEdgeOneIP string `json:"IsEdgeOneIP"`
}

type tencentCloudError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type tencentCloudAPIError struct {
	Code      string
	Message   string
	RequestID string
}

func (e *tencentCloudAPIError) Error() string {
	if e == nil {
		return "tencentcloud api error"
	}
	if e.RequestID != "" {
		return fmt.Sprintf("tencentcloud api error: %s: %s (requestId=%s)", e.Code, e.Message, e.RequestID)
	}
	return fmt.Sprintf("tencentcloud api error: %s: %s", e.Code, e.Message)
}

func normalizeTencentCloudEndpoint(raw, defaultHost string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultHost, nil
	}

	// Accept full URLs like "https://teo.tencentcloudapi.com".
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", xerrors.Errorf("invalid apiEndpoint: %w", err)
		}
		if u.Host == "" {
			return "", xerrors.New("invalid apiEndpoint: missing host")
		}
		return strings.ToLower(u.Host), nil
	}

	// Accept "host/path" and strip the path.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s), nil
}

func (v *tencentEdgeOneIPValidator) doTencentCloudJSONRequest(
	ctx context.Context,
	service string,
	version string,
	action string,
	payload []byte,
) ([]byte, error) {
	const (
		algorithm    = "TC3-HMAC-SHA256"
		httpMethod   = http.MethodPost
		canonicalURI = "/"
		contentType  = "application/json; charset=utf-8"
	)

	timestamp := time.Now().Unix()
	timestampStr := strconv.FormatInt(timestamp, 10)

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\n", contentType, v.endpoint)
	signedHeaders := "content-type;host"

	hashedRequestPayload := sha256Hex(payload)
	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		httpMethod,
		canonicalURI,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload)

	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	string2sign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		timestampStr,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)))

	signature := hex.EncodeToString(hmacSHA256(tc3SigningKey(v.secretKey, date, service), string2sign))
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		v.secretID,
		credentialScope,
		signedHeaders,
		signature)

	u := url.URL{Scheme: "https", Host: v.endpoint, Path: canonicalURI}
	req, err := http.NewRequestWithContext(ctx, httpMethod, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, xerrors.Errorf("build tencentcloud request: %w", err)
	}
	req.Host = v.endpoint
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Timestamp", timestampStr)
	req.Header.Set("Authorization", authorization)

	res, err := v.client.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("send tencentcloud request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("read tencentcloud response body: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, xerrors.Errorf("tencentcloud api http %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func tc3SigningKey(secretKey, date, service string) []byte {
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, service)
	return hmacSHA256(secretService, "tc3_request")
}
