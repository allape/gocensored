package censored

import (
	"encoding/hex"
	mysqlaes "github.com/allape/Go-MySQL-AES"
	"testing"
)

type MyCensored struct {
	Name string `censored:"hex"`
	Desc string `censored:"mysql-aes"`
}

func TestCensored(t *testing.T) {
	c := MyCensored{
		Name: "hello",
		Desc: "world",
	}

	if c.Name != "hello" {
		t.Fatalf("Name should be hello, but got %s", c.Name)
	}

	err := DefaultCensor.Encencor(&c)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if c.Name != "68656c6c6f" {
		t.Fatalf("Name should be 68656c6c6f, but got %s", c.Name)
	} else if c.Desc != "ed570fcde413167e5faf137052894005" {
		t.Fatalf("Desc should be ed570fcde413167e5faf137052894005, but got %s", c.Desc)
	}

	err = DefaultCensor.Decensor(&c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Name != "hello" {
		t.Fatalf("Name should be hello, but got %s", c.Name)
	} else if c.Desc != "world" {
		t.Fatalf("Desc should be world, but got %s", c.Desc)
	}
}

func TestRun(t *testing.T) {
	t.Log("hex hello = ", hex.EncodeToString([]byte("hello")))
	t.Log("hex world = ", hex.EncodeToString([]byte("world")))

	hello, err := mysqlaes.EncryptToHex("hello", "password")
	if err != nil {
		t.Fatalf("EncryptToHex failed: %v", err)
	}
	t.Log("MySQL AES hello = ", hello)

	world, err := mysqlaes.EncryptToHex("world", "password")
	if err != nil {
		t.Fatalf("EncryptToHex failed: %v", err)
	}
	t.Log("MySQL AES world = ", world)
}
