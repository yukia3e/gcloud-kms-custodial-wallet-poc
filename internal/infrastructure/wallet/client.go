package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/config"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/model"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/domain/repository"
	"github.com/yukia3e/gcloud-kms-custodial-wallet-poc/internal/util"
)

const (
	packageName = "kms"

	cryptoKeyVersion = 1
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

type kmsWallet struct {
	kmsClient      *kms.KeyManagementClient
	ethClient      *ethclient.Client
	gasStationRepo repository.GasStationRepository
}

func New(kmsClient *kms.KeyManagementClient, ethClient *ethclient.Client, gasStationRepo repository.GasStationRepository) repository.WalletRepository {
	return &kmsWallet{
		kmsClient:      kmsClient,
		ethClient:      ethClient,
		gasStationRepo: gasStationRepo,
	}
}

func (k *kmsWallet) CreateCryptoKey(ctx context.Context, userID string) (string, error) {
	if userID == "" {
		return "", util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("userID is empty"))
	}

	parent, err := k.generateUserKeyParent(userID)
	if err != nil {
		return "", util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to generate user key parent: %w", err))
	}

	cryptoKey, err := k.kmsClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: userID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			},
		},
	})
	if err != nil {
		return "", util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to create crypto key: %w", err))
	}

	return cryptoKey.Name, nil
}

func (k *kmsWallet) GetHexAddress(ctx context.Context, userID string) (string, error) {
	keyVersion, err := k.userKeyVersion(userID)
	if err != nil {
		return "", util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to get user key version: %w", err))
	}

	address, err := k.getAddress(ctx, keyVersion)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}

func (k *kmsWallet) SendTransaction(ctx context.Context, userID string, req repository.SendTransactionRequest) error {
	keyVersion, err := k.userKeyVersion(userID)
	if err != nil {
		return util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to get user key version: %w", err))
	}

	// From
	fromAddress, err := k.getAddress(ctx, keyVersion)
	if err != nil {
		return util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to get address: %w", err))
	}
	log.Debug().Str("fromAddress", fromAddress.Hex()).Msg("success")

	// To
	var toAddress *common.Address
	if req.To != nil {
		toAddress = util.Pointer(common.HexToAddress(*req.To))
	}

	// Nonce
	nonce, err := k.ethClient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to get nonce: %w", err))
	}

	// GasTipCap, GasFeeCap
	gasPriceRecommendations, err := k.gasStationRepo.GetGasPriceRecommendations(ctx)
	if err != nil {
		log.Error().Msg(util.WrapLogMessage(packageName, util.FuncName(), fmt.Sprintf("failed to get gas price recommendations: %v", err)))
		// TODO: Polygon Gas Station が長期にわたって Down した場合にどうするかは別途検討
	}

	var gasTipCap, gasFeeCap *big.Int
	if req.PriorityType == nil {
		gasTipCap = big.NewInt(int64(gasPriceRecommendations.Standard.MaxPriorityFee * 1e9))
		gasFeeCap = big.NewInt(int64(gasPriceRecommendations.Standard.MaxFee * 1e9))
	} else {
		switch *req.PriorityType {
		case repository.TransactionPriorityTypeSafeLow:
			gasTipCap = big.NewInt(int64(gasPriceRecommendations.SafeLow.MaxPriorityFee * 1e9))
			gasFeeCap = big.NewInt(int64(gasPriceRecommendations.SafeLow.MaxFee * 1e9))
		case repository.TransactionPriorityTypeFast:
			gasTipCap = big.NewInt(int64(gasPriceRecommendations.Fast.MaxPriorityFee * 1e9))
			gasFeeCap = big.NewInt(int64(gasPriceRecommendations.Fast.MaxFee * 1e9))
		default:
			gasTipCap = big.NewInt(int64(gasPriceRecommendations.Standard.MaxPriorityFee * 1e9))
			gasFeeCap = big.NewInt(int64(gasPriceRecommendations.Standard.MaxFee * 1e9))
		}
	}

	// GasLimit
	gasLimit := config.GetGasLimit()

	signTrxReq := SignTransactionRequest{
		From:      util.Pointer(fromAddress),
		To:        toAddress,
		ChainID:   model.GetChainID(),
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		GasLimit:  gasLimit,
		Data:      req.Data,
		Value:     req.Value,
	}
	log.Info().Any("signTrxReq", signTrxReq).Msg("signTrxReq !!!")
	signedTx, err := k.signTransaction(ctx, keyVersion, signTrxReq)
	if err != nil {
		return util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to sign transaction: %w", err))
	}

	// Send transaction
	err = k.ethClient.SendTransaction(ctx, signedTx)
	if err != nil {
		return util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to send transaction: %w", err))
	}

	return nil
}

func (k *kmsWallet) userKeyVersion(userID string) (string, error) {
	parent, err := k.generateUserKeyParent(userID)
	if err != nil {
		return "", util.WrapErrorForLog(packageName, util.FuncName(), fmt.Errorf("failed to generate user key parent: %w", err))
	}

	return fmt.Sprintf("%s/cryptoKeyVersions/%d", parent, cryptoKeyVersion), nil
}

func (k *kmsWallet) generateUserKeyParent(userID string) (string, error) {
	return fmt.Sprintf("projects/%s/locations/asia-northeast1/keyRings/%s/cryptoKeys/%s", config.MustGetGCPProjectID(), config.MustGetKeyRingID(), userID), nil
}

func (k *kmsWallet) getAddress(ctx context.Context, keyVersion string) (common.Address, error) {
	funcName := util.FuncName()

	publicKeyResponse, err := k.kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyVersion,
	})
	if err != nil {
		return common.Address{}, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: %w", err))
	}

	if publicKeyResponse.Name != keyVersion {
		return common.Address{}, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: invalid key name"))
	}

	publicKeyPEM := publicKeyResponse.Pem
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return common.Address{}, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to decode public key"))
	}

	pubKey, err := getPublicKeyFromDecodedPEM(block)
	if err != nil {
		return common.Address{}, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: %w", err))
	}

	addr := crypto.PubkeyToAddress(pubKey)

	return addr, nil
}

func (k *kmsWallet) getPublicKey(ctx context.Context, keyVersion string) (*ecdsa.PublicKey, error) {
	funcName := util.FuncName()

	publicKeyResponse, err := k.kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyVersion,
	})
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: %w", err))
	}
	if publicKeyResponse.Name != keyVersion {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: invalid key name"))
	}
	publicKeyPEM := publicKeyResponse.Pem
	if publicKeyPEM == "" {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: empty PEM"))
	}
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	if int64(crc32c([]byte(publicKeyPEM))) != publicKeyResponse.GetPemCrc32C().GetValue() {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: invalid CRC32"))
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to decode public key"))
	}
	pubKey, err := getPublicKeyFromDecodedPEM(block)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: %w", err))
	}

	return &pubKey, nil
}

type SignTransactionRequest struct {
	From      *common.Address
	ChainID   *big.Int        // destination chain ID
	Nonce     uint64          // nonce of sender account
	GasTipCap *big.Int        // a.k.a. maxPriorityFeePerGas
	GasFeeCap *big.Int        // a.k.a. maxFeePerGas
	GasLimit  uint64          // gas limit
	To        *common.Address `rlp:"nil"` // nil means contract creation
	Data      []byte          // contract invocation input data
	Value     *big.Int        // wei amount
}

func (k *kmsWallet) signTransaction(ctx context.Context, keyVersion string, req SignTransactionRequest) (*types.Transaction, error) {
	funcName := util.FuncName()

	address, err := k.getAddress(ctx, keyVersion)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get address: %w", err))
	}

	if req.From != nil && address != *req.From {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get address: invalid address, expected %s, got %s", req.From.Hex(), address.Hex()))
	}

	// DynamicFeeTx
	uTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   req.ChainID,
		Nonce:     req.Nonce,
		GasTipCap: req.GasTipCap,
		GasFeeCap: req.GasFeeCap,
		Gas:       req.GasLimit,
		To:        req.To,
		Value:     req.Value,
		Data:      req.Data,
	})
	signer := types.NewLondonSigner(req.ChainID)
	txHash := signer.Hash(uTx)

	signature, err := k.sign(ctx, keyVersion, txHash[:])
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to sign: %w", err))
	}

	signedTx, err := uTx.WithSignature(signer, signature)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to sign transaction: %w", err))
	}
	return signedTx, nil
}

func (k *kmsWallet) sign(ctx context.Context, keyVersion string, hash []byte) ([]byte, error) {
	funcName := util.FuncName()

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	digestCRC32C := crc32c(hash)

	signResponse, err := k.kmsClient.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: keyVersion,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: hash,
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	})
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to sign digest: %w", err))
	}

	if len(signResponse.Signature) == 0 {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to sign digest: empty signature"))
	}

	if int64(crc32c(signResponse.Signature)) != signResponse.SignatureCrc32C.Value {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("AsymmetricSign: response corrupted in-transit"))
	}

	r, s, err := parseSignature(signResponse.Signature)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to parse signature: %w", err))
	}

	pubKey, err := k.getPublicKey(ctx, keyVersion)
	if err != nil {
		return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to get public key: %w", err))
	}

	for _, v := range []int{0, 1} {
		candidateSignature := make([]byte, 65)
		copy(candidateSignature[:32], r.Bytes())
		copy(candidateSignature[32:64], s.Bytes())
		candidateSignature[64] = byte(v)

		candidateRawPublicKey, err := crypto.Ecrecover(hash, candidateSignature)
		if err != nil {
			return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to recover public key: %w", err))
		}

		candidatePublicKey, err := crypto.UnmarshalPubkey(candidateRawPublicKey)
		if err != nil {
			return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to parse public key: %w", err))
		}

		if candidatePublicKey.Equal(pubKey) {
			return candidateSignature, nil
		}
	}

	return nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to sign digest: invalid signature"))
}

func getPublicKeyFromDecodedPEM(block *pem.Block) (ecdsa.PublicKey, error) {
	funcName := util.FuncName()

	var pki struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(block.Bytes, &pki)
	if err != nil {
		return ecdsa.PublicKey{}, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to unmarshal public key: %w", err))
	}
	asn1Data := pki.PublicKey.RightAlign()
	_, x, y := asn1Data[0], asn1Data[1:33], asn1Data[33:]
	xBig := new(big.Int)
	xBig.SetBytes(x)
	yBig := new(big.Int)
	yBig.SetBytes(y)
	pubKey := ecdsa.PublicKey{Curve: crypto.S256(), X: xBig, Y: yBig}

	return pubKey, nil
}

func parseSignature(signature []byte) (r *big.Int, s *big.Int, err error) {
	funcName := util.FuncName()

	sig := new(struct {
		R *big.Int
		S *big.Int
	})

	_, err = asn1.Unmarshal(signature, sig)
	if err != nil {
		return nil, nil, util.WrapErrorForLog(packageName, funcName, fmt.Errorf("failed to unmarshal signature: %w", err))
	}

	if sig.S.Cmp(secp256k1halfN) > 0 {
		sig.S = new(big.Int).Sub(secp256k1N, sig.S)
	}

	return sig.R, sig.S, nil
}
