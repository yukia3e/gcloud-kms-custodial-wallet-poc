package repository

import "math/big"

type SendTransactionRequest struct {
	From  *string
	To    *string  // nil means contract creation
	Data  []byte   // contract invocation input data
	Value *big.Int // wei amount

	PriorityType *TransactionPriorityType
}

type TransactionPriorityType int32

const (
	TransactionPriorityTypeUnspecified TransactionPriorityType = 0
	TransactionPriorityTypeSafeLow     TransactionPriorityType = 1
	TransactionPriorityTypeStandard    TransactionPriorityType = 2
	TransactionPriorityTypeFast        TransactionPriorityType = 3
)

type CreateCryptoKeyRequest struct {
	UserID string
}
