package censored

import (
	"encoding/hex"
	mysqlaes "github.com/allape/Go-MySQL-AES"
)

// MySQLAESCensor is a strong censor, but not searchable in the database.
type MySQLAESCensor struct {
	Codec
}

func (c *MySQLAESCensor) Encode(value string, password []byte) (HexString, error) {
	bs, e := mysqlaes.Encrypt([]byte(value), password)
	return HexString(hex.EncodeToString(bs)), e
}

func (c *MySQLAESCensor) Decode(value HexString, password []byte) (string, error) {
	bs, e := hex.DecodeString(string(value))
	if e != nil {
		return "", e
	}

	bs, e = mysqlaes.Decrypt(bs, password)
	return string(bs), e
}
