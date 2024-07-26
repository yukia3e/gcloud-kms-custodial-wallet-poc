package http

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/model"
)

type mockTransport struct {
	Req      *http.Request
	Response *http.Response
	Err      error
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.Req = req
	return m.Response, m.Err
}

func TestHTTP_GetGasPriceRecommendations(t *testing.T) {
	tests := []struct {
		name           string
		mockRes        *http.Response
		wantErrMessage string
		want           *model.GasPriceRecommendations
	}{
		{
			name: "success",
			mockRes: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"safeLow":{"maxPriorityFee":30,"maxFee":30.000000016},"standard":{"maxPriorityFee":31,"maxFee":31.000000016},"fast":{"maxPriorityFee":32,"maxFee":32.000000016},"estimatedBaseFee":1.6e-8,"blockTime":2,"blockNumber":47841869}`)),
			},
			want: &model.GasPriceRecommendations{
				SafeLow: &model.GasPriceRecommendation{
					MaxPriorityFee: 30,
					MaxFee:         30.000000016,
				},
				Standard: &model.GasPriceRecommendation{
					MaxPriorityFee: 31,
					MaxFee:         31.000000016,
				},
				Fast: &model.GasPriceRecommendation{
					MaxPriorityFee: 32,
					MaxFee:         32.000000016,
				},
				EstimatedBaseFee: 1.6e-8,
				BlockTime:        2,
				BlockNumber:      47841869,
			},
		},
		{
			name: "error - status code not 200",
			mockRes: &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
			},
			wantErrMessage: "http.GetGasPriceRecommendations: status code not 200: 404",
		},
		{
			name: "error - invalid json",
			mockRes: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`invalid json`)),
			},
			wantErrMessage: "http.GetGasPriceRecommendations: error decoding response body: invalid character 'i' looking for beginning of value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{
				Transport: &mockTransport{
					Response: tt.mockRes,
				},
			}

			c := NewGasStationClient(httpClient)
			res, err := c.GetGasPriceRecommendations(context.Background())
			if tt.wantErrMessage != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.wantErrMessage)
				return
			}

			assert.NoError(t, err)
			if diff := cmp.Diff(tt.want, res, protocmp.Transform()); diff != "" {
				t.Errorf("GetGasPriceRecommendations() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
