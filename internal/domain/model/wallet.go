package model

import (
	"math/big"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/config"
)

const (
	BlockchainDecimalMainnet      = 137
	BlockchainDecimalAmoy         = 80002
	BlockchainDecimalHardhatLocal = 1337
)

func GetChainID() *big.Int {
	if config.IsProduction() {
		return big.NewInt(BlockchainDecimalMainnet)
	}
	if config.IsStaging() || config.IsDevelopment() {
		return big.NewInt(BlockchainDecimalAmoy)
	}

	return big.NewInt(BlockchainDecimalHardhatLocal)
}

type GasPriceRecommendation struct {
	MaxPriorityFee float32
	MaxFee         float32
}

type GasPriceRecommendations struct {
	SafeLow          *GasPriceRecommendation
	Standard         *GasPriceRecommendation
	Fast             *GasPriceRecommendation
	EstimatedBaseFee float32
	BlockTime        int64
	BlockNumber      int64
}
