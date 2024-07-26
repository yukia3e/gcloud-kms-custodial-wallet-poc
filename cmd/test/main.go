package main

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/config"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/repository"
	appHttp "github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/infrastructure/http"
	wallet "github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/infrastructure/wallet"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/util"
)

const (
	packageName = "main"

	sampleUserID = "00000000-0000-0000-0000-000000000001"
)

func main() {
	const funcName = "main"

	ctx := context.Background()

	os.Setenv("FIREBASE_CREDENTIAL_FILE_PATH", "../../.gcloud/credentials.json")

	opt := option.WithCredentialsFile(config.GetCredentialFilePath())
	kmsClient, err := kms.NewKeyManagementClient(ctx, opt)
	if err != nil {
		log.Error().Msg(util.WrapLogMessage(packageName, funcName, fmt.Sprintf("failed to create wallet client: %v", err)))
		return
	}
	defer kmsClient.Close()

	rpcEndpoint := config.MustGetRPCEndpoint()
	ethClient, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		log.Error().Msg(util.WrapLogMessage(packageName, funcName, fmt.Sprintf("failed to dial eth client: %v", err)))
		return
	}
	defer ethClient.Close()
	httpClient := appHttp.NewGasStationClient(&http.Client{})

	kmsWallet := wallet.New(kmsClient, ethClient, httpClient)

	// Hardhat test account
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// 送信するEtherの量 (wei)
	value := big.NewInt(1000)

	// Create crypto key
	// if _, err := kmsWallet.CreateCryptoKey(ctx, userID); err != nil {
	// 	log.Error().Msg(util.WrapLogMessage(packageName, funcName, fmt.Sprintf("failed to create crypto key: %v", err)))
	// 	return
	// }

	// Get kms wallet's hex address
	from, err := kmsWallet.GetHexAddress(ctx, sampleUserID)
	if err != nil {
		log.Error().Msg(util.WrapLogMessage(packageName, funcName, fmt.Sprintf("failed to get hex address: %v", err)))
		return
	}

	// Send transaction
	err = kmsWallet.SendTransaction(ctx, sampleUserID, repository.SendTransactionRequest{
		From:  util.Pointer(from),
		To:    &to,
		Value: value,
	})
	if err != nil {
		log.Error().Msg(util.WrapLogMessage(packageName, funcName, fmt.Sprintf("failed to send transaction: %v", err)))
		return
	}

	log.Info().Msg(util.WrapLogMessage(packageName, funcName, "success"))
}
