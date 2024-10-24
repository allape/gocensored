# Go Censored

String field encryption for `struct`, most used in GORM with MySQL.

## Example

Also see [censored_test.go](censored_test.go).

```go
package main

import censored "github.com/allape/gocensored"

type CompanyData struct {
	Info1       string `censored:"mysql-aes"`
	Info2       string `censored:"mysql-aes"`
	PublicInfo1 string `censored:"hex"`
}

func main() {
	info := CompanyData{
		Info1:       "secret1",
		Info2:       "secret2",
		PublicInfo1: "public1",
	}

	censor := censored.NewDefaultCensor(&censored.CensorConfig{
		Password: []byte("1234_6789"),
	})

	err := censor.Encencor(&info)
	if err != nil {
		panic(err)
	}
}

```
