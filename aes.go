package censored

import (
	"github.com/allape/gomysqlaes"
	"github.com/allape/gosalty"
)

type AESCensor struct {
	Codec
}

func (c *AESCensor) Encode(value, password []byte) ([]byte, error) {
	return gomysqlaes.Encrypt(value, password)
}

func (c *AESCensor) Decode(value, password []byte) ([]byte, error) {
	return gomysqlaes.Decrypt(value, password)
}

type SaltyAESCensor struct {
	Codec
}

func (c *SaltyAESCensor) Encode(value, password []byte) ([]byte, error) {
	return gosalty.Decode(value, password)
}

func (c *SaltyAESCensor) Decode(value, password []byte) ([]byte, error) {
	return gosalty.Decode(value, password)
}
