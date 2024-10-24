package censored

import "reflect"

type HandleField func(field reflect.Value, fieldType reflect.StructField) error

func WalkThroughStringFields(record any, handle HandleField) error {
	v := reflect.ValueOf(record).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		if fieldType.Type.Kind() != reflect.String {
			continue
		}

		err := handle(field, fieldType)
		if err != nil {
			return err
		}
	}

	return nil
}
