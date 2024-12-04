# Go Censored

String field encryption for `struct`, most used in GORM with MySQL.

## Example

Also see [censored_test.go](censored_test.go).

```go
package main

import "github.com/allape/gocensored"

type CompanyData struct {
	Info1       string `censored:"aes.hex"`
	Info2       string `censored:"aes.base64"`
	Info3       string `censored:"saltyaes.urlbase64"`
	PublicInfo1 string `censored:".hex"`
}

func main() {
	info := CompanyData{
		Info1:       "secret1",
		Info2:       "secret2",
		Info3:       "secret3",
		PublicInfo1: "public1",
	}

	censor, err := censored.NewDefaultCensor(&gocensored.Config{
		Password: []byte("1234_6789"),
	})
	if err != nil {
        panic(err)
    }

	err = censor.Encencor(&info)
	if err != nil {
		panic(err)
	}
}

```
