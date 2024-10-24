package censored

import (
	"fmt"
	"reflect"
	"sync"
)

type HexString string

type Codec interface {
	Encode(value string, password []byte) (HexString, error)
	Decode(value HexString, password []byte) (string, error)
}

const TagName = "censored"

type CensorConfig struct {
	Password []byte
	TagName  string
}

type Censor struct {
	locker sync.Locker
	codecs map[string]Codec

	Config CensorConfig
}

func (r *Censor) RegisterCodec(name string, codec Codec, enforced bool) error {
	r.locker.Lock()
	defer func() {
		r.locker.Unlock()
	}()

	if !enforced {
		if _, ok := r.codecs[name]; ok {
			return fmt.Errorf("censor %s already exists", name)
		}
	}

	r.codecs[name] = codec

	return nil
}

func (r *Censor) Encencor(record any) error {
	return WalkThroughStringFields(record, func(field reflect.Value, fieldType reflect.StructField) error {
		tag := fieldType.Tag.Get(r.Config.TagName)
		codec, ok := r.codecs[tag]
		if !ok {
			return fmt.Errorf("censor %s not found", tag)
		}

		encrypted, err := codec.Encode(field.String(), r.Config.Password)
		if err != nil {
			return err
		}
		field.SetString(string(encrypted))

		return nil
	})
}

func (r *Censor) Decensor(record any) error {
	return WalkThroughStringFields(record, func(field reflect.Value, fieldType reflect.StructField) error {
		tag := fieldType.Tag.Get(r.Config.TagName)
		codec, ok := r.codecs[tag]
		if !ok {
			return fmt.Errorf("censor %s not found", tag)
		}

		decrypted, err := codec.Decode(HexString(field.String()), r.Config.Password)
		if err != nil {
			return err
		}
		field.SetString(decrypted)

		return nil
	})
}

func NewDefaultCensor(config *CensorConfig) *Censor {
	if config == nil {
		config = &CensorConfig{}
	}

	if config.TagName == "" {
		config.TagName = TagName
	}
	if config.Password == nil {
		config.Password = []byte("password")
	}

	censor := &Censor{
		locker: &sync.Mutex{},
		codecs: make(map[string]Codec),
		Config: *config,
	}

	_ = censor.RegisterCodec("hex", &HexCensor{}, true)
	_ = censor.RegisterCodec("mysql-aes", &MySQLAESCensor{}, true)

	return censor
}

var DefaultCensor = NewDefaultCensor(nil)
