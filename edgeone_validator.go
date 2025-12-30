package traefik_edgeone_ip

import (
	"context"
	"math"
	"net/netip"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

type EdgeOneIPValidator interface {
	Validate(ctx context.Context, ip netip.Addr) (bool, error)
}

type tencentEdgeOneIPValidator struct {
	client *teo.Client
}

func newTencentEdgeOneIPValidator(secretID, secretKey, apiEndpoint string, timeoutSeconds int) (*tencentEdgeOneIPValidator, error) {
	if apiEndpoint == "" {
		apiEndpoint = "teo.tencentcloudapi.com"
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = apiEndpoint
	cpf.HttpProfile.ReqTimeout = timeoutSeconds

	credential := common.NewCredential(secretID, secretKey)
	client, err := teo.NewClient(credential, "", cpf)
	if err != nil {
		return nil, err
	}

	return &tencentEdgeOneIPValidator{client: client}, nil
}

func durationToTimeoutSeconds(durSeconds float64) int {
	if durSeconds <= 0 {
		return 0
	}
	return int(math.Ceil(durSeconds))
}

func (v *tencentEdgeOneIPValidator) Validate(_ context.Context, ip netip.Addr) (bool, error) {
	req := teo.NewDescribeIPRegionRequest()
	req.IPs = []*string{common.StringPtr(ip.String())}

	resp, err := v.client.DescribeIPRegion(req)
	if err != nil {
		return false, err
	}

	for _, info := range resp.Response.IPRegionInfo {
		if info == nil || info.IsEdgeOneIP == nil || *info.IsEdgeOneIP != "yes" || info.IP == nil {
			continue
		}
		parsed, err := netip.ParseAddr(*info.IP)
		if err != nil {
			continue
		}
		if parsed == ip {
			return true, nil
		}
	}

	return false, nil
}
