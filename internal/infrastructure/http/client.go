package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/config"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/model"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/repository"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/util"
)

const packageName = "http"

type client struct {
	httpClient *http.Client
}

func NewGasStationClient(httpClient *http.Client) repository.GasStationRepository {
	return &client{
		httpClient: httpClient,
	}
}

type (
	ExtraHeader struct {
		Key   string
		Value string
	}

	ErrorRes struct {
		Body   any
		Status int
	}
)

type GasPriceRecommendations struct {
	SafeLow     *GasPriceRecommendation `json:"safeLow"`
	Standard    *GasPriceRecommendation `json:"standard"`
	Fast        *GasPriceRecommendation `json:"fast"`
	BaseFee     float32                 `json:"estimatedBaseFee"`
	BlockTime   int64                   `json:"blockTime"`
	BlockNumber int64                   `json:"blockNumber"`
}

type GasPriceRecommendation struct {
	MaxPriorityFee float32 `json:"maxPriorityFee"`
	MaxFee         float32 `json:"maxFee"`
}

func (c *client) GetGasPriceRecommendations(ctx context.Context) (*model.GasPriceRecommendations, error) {
	funcName := util.FuncName()

	endpoint := getGasStationEndpoint()

	res, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("error making request: %w", err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("status code not 200: %d", res.StatusCode))
	}

	var tmp GasPriceRecommendations
	if err := json.NewDecoder(res.Body).Decode(&tmp); err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("error decoding response body: %w", err))
	}

	if tmp.SafeLow == nil || tmp.Standard == nil || tmp.Fast == nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("error decoding response body: gas price recommendations are not set"))
	}

	gasPriceRecommendations := model.GasPriceRecommendations{
		SafeLow: &model.GasPriceRecommendation{
			MaxPriorityFee: tmp.SafeLow.MaxPriorityFee,
			MaxFee:         tmp.SafeLow.MaxFee,
		},
		Standard: &model.GasPriceRecommendation{
			MaxPriorityFee: tmp.Standard.MaxPriorityFee,
			MaxFee:         tmp.Standard.MaxFee,
		},
		Fast: &model.GasPriceRecommendation{
			MaxPriorityFee: tmp.Fast.MaxPriorityFee,
			MaxFee:         tmp.Fast.MaxFee,
		},
		EstimatedBaseFee: tmp.BaseFee,
		BlockTime:        tmp.BlockTime,
		BlockNumber:      tmp.BlockNumber,
	}

	return &gasPriceRecommendations, nil
}

func (c *client) doRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("error creating request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("error do request: %w", err))
	}

	return resp, nil
}

func getGasStationEndpoint() string {
	if config.IsProduction() {
		return "https://gasstation.polygon.technology/v2"
	}
	if config.IsStaging() || config.IsDevelopment() {
		return "https://gasstation-testnet.polygon.technology/v2"
	}
	return "https://gasstation-testnet.polygon.technology/v2"
}
