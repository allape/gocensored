package censored

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

type Codec interface {
	Encode(value, password []byte) ([]byte, error)
	Decode(value, password []byte) ([]byte, error)
}

type Transformer interface {
	Encode(value []byte) (string, error)
	Decode(value string) ([]byte, error)
}

type (
	CodecName       string
	TransformerName string
)

type TagContent string

func (t TagContent) Get() (CodecName, TransformerName, error) {
	if t == "" {
		return "", "", nil
	}

	seg := strings.Split(string(t), ".")
	if len(seg) != 2 {
		return "", "", fmt.Errorf("invalid tag content")
	}

	if seg[1] == "" {
		seg[1] = "hex"
	}

	return CodecName(seg[0]), TransformerName(seg[1]), nil
}

const DefaultTagName = "censored"

type Censor struct {
	locker sync.Locker

	codecs       map[CodecName]Codec
	transformers map[TransformerName]Transformer

	Config *Config
}

func (r *Censor) RegisterCodec(name CodecName, codec Codec, enforced bool) error {
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

func (r *Censor) RegisterTransformer(name TransformerName, transformer Transformer, enforced bool) error {
	r.locker.Lock()
	defer func() {
		r.locker.Unlock()
	}()

	if !enforced {
		if _, ok := r.transformers[name]; ok {
			return fmt.Errorf("transformer %s already exists", name)
		}
	}

	r.transformers[name] = transformer

	return nil
}

func (r *Censor) Encencor(record any) error {
	return WalkThroughStringFields(record, func(field reflect.Value, fieldType reflect.StructField) error {
		tag := fieldType.Tag.Get(r.Config.TagName)
		if tag == "" {
			return nil
		}

		codecName, transName, err := TagContent(tag).Get()
		if err != nil {
			return err
		}

		encrypted := []byte(field.String())

		if codecName != "" {
			codec, ok := r.codecs[codecName]
			if !ok {
				return fmt.Errorf("censor %s not found", tag)
			}
			encrypted, err = codec.Encode(encrypted, r.Config.Password)
			if err != nil {
				return err
			}
		}

		transformer, ok := r.transformers[transName]
		if !ok {
			return fmt.Errorf("transformer %s not found", tag)
		}

		encoded, err := transformer.Encode(encrypted)
		if err != nil {
			return err
		}

		field.SetString(encoded)

		return nil
	})
}

func (r *Censor) Decensor(record any) error {
	return WalkThroughStringFields(record, func(field reflect.Value, fieldType reflect.StructField) error {
		tag := fieldType.Tag.Get(r.Config.TagName)
		if tag == "" {
			return nil
		}

		codecName, transName, err := TagContent(tag).Get()
		if err != nil {
			return err
		}

		transformer, ok := r.transformers[transName]
		if !ok {
			return fmt.Errorf("transformer %s not found", tag)
		}

		encoded := field.String()

		encrypted, err := transformer.Decode(encoded)
		if err != nil {
			return err
		}

		if codecName != "" {
			codec, ok := r.codecs[codecName]
			if !ok {
				return fmt.Errorf("censor %s not found", tag)
			}
			decrypted, err := codec.Decode(encrypted, r.Config.Password)
			if err != nil {
				return err
			}
			field.SetString(string(decrypted))
		} else {
			field.SetString(string(encrypted))
		}

		return nil
	})
}

type Config struct {
	TagName  string
	Password []byte
}

func NewDefaultCensor(config *Config) (_ *Censor, err error) {
	if config == nil {
		config = &Config{}
	}

	if config.TagName == "" {
		config.TagName = DefaultTagName
	}
	if config.Password == nil {
		password := make([]byte, 32)
		n, err := rand.Read(password)
		if err != nil {
			return nil, err
		} else if n != 32 {
			return nil, fmt.Errorf("invalid password length")
		}
		config.Password = password
	}

	censor := &Censor{
		locker: &sync.Mutex{},

		codecs:       map[CodecName]Codec{},
		transformers: map[TransformerName]Transformer{},

		Config: config,
	}

	err = censor.RegisterTransformer("base64", &StdBase64Transformer{}, true)
	if err != nil {
		return nil, err
	}
	err = censor.RegisterTransformer("stdbase64", &StdBase64Transformer{}, true)
	if err != nil {
		return nil, err
	}
	err = censor.RegisterTransformer("urlbase64", &URLBase64Transformer{}, true)
	if err != nil {
		return nil, err
	}
	err = censor.RegisterTransformer("hex", &HexTransformer{}, true)
	if err != nil {
		return nil, err
	}

	err = censor.RegisterCodec("aes", &AESCensor{}, true)
	if err != nil {
		return nil, err
	}
	err = censor.RegisterCodec("saltyaes", &SaltyAESCensor{}, true)
	if err != nil {
		return nil, err
	}

	return censor, nil
}
