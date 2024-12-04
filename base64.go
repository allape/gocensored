package censored

import (
	"encoding/base64"
)

type StdBase64Transformer struct {
	Transformer
}

func (c *StdBase64Transformer) Encode(value []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(value), nil
}

func (c *StdBase64Transformer) Decode(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

type URLBase64Transformer struct {
	Transformer
}

func (c *URLBase64Transformer) Encode(value []byte) (string, error) {
	return base64.URLEncoding.EncodeToString(value), nil
}

func (c *URLBase64Transformer) Decode(value string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(value)
}
