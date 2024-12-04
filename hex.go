package censored

import "encoding/hex"

type HexTransformer struct {
	Transformer
}

func (c *HexTransformer) Encode(value []byte) (string, error) {
	return hex.EncodeToString(value), nil
}

func (c *HexTransformer) Decode(value string) ([]byte, error) {
	return hex.DecodeString(value)
}
