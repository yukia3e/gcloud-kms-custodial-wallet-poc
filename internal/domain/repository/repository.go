package repository

import (
	"context"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/model"
)

// WalletRepository
type WalletRepository interface {
	// CreateCryptoKey クリプトキーを作成し、keyVersionを取得
	CreateCryptoKey(ctx context.Context, userID string) (string, error)
	// GetHexAddress アドレスを取得
	GetHexAddress(ctx context.Context, userID string) (string, error)
	// SendTransaction トランザクションを送信
	SendTransaction(ctx context.Context, userID string, req SendTransactionRequest) error
}

// GasStationRepository
type GasStationRepository interface {
	GetGasPriceRecommendations(ctx context.Context) (*model.GasPriceRecommendations, error)
}
