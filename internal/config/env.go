package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog/log"
)

const DefaultGasLimit = 21000

func GetEnvironment() string {
	return os.Getenv("APP_ENV")
}

func IsLocal() bool {
	return GetEnvironment() == "local"
}

func IsDevelopment() bool {
	return GetEnvironment() == "local" || GetEnvironment() == "development"
}

func IsStaging() bool {
	return GetEnvironment() == "staging"
}

func IsProduction() bool {
	return GetEnvironment() == "production"
}

func MustGetGCPProjectID() string {
	gcpProjectID := os.Getenv("GCP_PROJECT_ID")
	if gcpProjectID == "" {
		panic("GCP_PROJECT_ID is not set")
	}

	return gcpProjectID
}

func MustGetKeyRingID() string {
	keyRingID := os.Getenv("KEY_RING_ID")
	if keyRingID == "" {
		panic("KEY_RING_ID is not set")
	}

	return keyRingID
}

func MustGetRPCEndpoint() string {
	rpcEndpoint := os.Getenv("RPC_ENDPOINT")
	if rpcEndpoint == "" {
		panic("RPC_ENDPOINT is not set")
	}

	return rpcEndpoint
}

func GetGasLimit() uint64 {
	gasLimitStr := os.Getenv("GAS_LIMIT")
	if gasLimitStr == "" {
		return DefaultGasLimit
	}
	gasLimit, err := strconv.ParseUint(gasLimitStr, 10, 64)
	if err != nil {
		log.Error().Msgf(fmt.Sprintf("config.GetGasLimit: failed to parse gas limit: %v", err.Error()))
		return DefaultGasLimit
	}
	return gasLimit
}

func GetCredentialFilePath() string {
	return os.Getenv("FIREBASE_CREDENTIAL_FILE_PATH")
}
