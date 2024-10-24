package censored

import "encoding/hex"

// HexCensor is a super weak censor, but searchable in the database.
type HexCensor struct {
	Codec
}

func (c *HexCensor) Encode(value string, _ []byte) (HexString, error) {
	return HexString(hex.EncodeToString([]byte(value))), nil
}

func (c *HexCensor) Decode(value HexString, _ []byte) (string, error) {
	s, e := hex.DecodeString(string(value))
	return string(s), e
}
