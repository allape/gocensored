package censored

import (
	"testing"
)

type MyCensored struct {
	Name  string `censored:".hex"`
	Desc  string `censored:"aes.base64"`
	Plain string `censored:"saltyaes.urlbase64"`
}

func TestCensored(t *testing.T) {
	c := MyCensored{
		Name:  "hello",
		Desc:  "world",
		Plain: "my little tiny teeny secret",
	}

	if c.Name != "hello" {
		t.Fatalf("Name should be hello, but got %s", c.Name)
	}

	censor, err := NewDefaultCensor(&Config{
		Password: []byte("123567"),
	})
	if err != nil {
		t.Fatalf("NewDefaultCensor failed: %v", err)
	}

	err = censor.Encencor(&c)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if c.Name != "68656c6c6f" {
		t.Fatalf("Name should be 68656c6c6f, but got %s", c.Name)
	} else if c.Desc != "b/4tTBUHHM+S+Ap36f4nbA==" {
		t.Fatalf("Desc should be b/4tTBUHHM+S+Ap36f4nbA==, but got %s", c.Desc)
	} else if c.Plain == "my little tiny teeny secret" {
		t.Fatalf("Plain should not be my little tiny teeny secret, but got %s", c.Plain)
	}

	t.Log(c.Name)
	t.Log(c.Desc)
	t.Log(c.Plain)

	err = censor.Decensor(&c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Name != "hello" {
		t.Fatalf("Name should be hello, but got %s", c.Name)
	} else if c.Desc != "world" {
		t.Fatalf("Desc should be world, but got %s", c.Desc)
	} else if c.Plain != "my little tiny teeny secret" {
		t.Fatalf("Plain should be my little tiny teeny secret, but got %s", c.Plain)
	}
}
