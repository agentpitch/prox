package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeJSON rejects ambiguous documents before encoding/json can silently
// overwrite duplicate fields or interpret null as a zero-valued setting.
// Empty collections may be null, matching exported config documents.
func DecodeJSON(data []byte, target any) error {
	if len(data) > MaxConfigBytes {
		return fmt.Errorf("JSON exceeds %d-byte limit", MaxConfigBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON must be valid UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return fmt.Errorf("JSON target must be a non-nil pointer")
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	if err := scanJSON(scan, typ.Elem(), 0); err != nil {
		return err
	}
	if _, err := scan.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func scanJSON(decoder *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if typ == nil || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map || typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Interface {
			return nil
		}
		return fmt.Errorf("null is not allowed for %s", typ)
	}
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil // encoding/json validates scalar types and custom unmarshallers.
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			rawKey, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := rawKey.(string)
			if !ok {
				return fmt.Errorf("JSON object key must be a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = true
			var fieldType reflect.Type
			if typ != nil && typ.Kind() == reflect.Struct {
				for i := 0; i < typ.NumField(); i++ {
					field := typ.Field(i)
					name := strings.Split(field.Tag.Get("json"), ",")[0]
					if name == "" {
						name = field.Name
					}
					if field.PkgPath == "" && name != "-" && name == key {
						fieldType = field.Type
						break
					}
				}
				if fieldType == nil {
					return fmt.Errorf("unknown JSON field %q", key)
				}
			} else if typ != nil && typ.Kind() == reflect.Map {
				fieldType = typ.Elem()
			}
			if err := scanJSON(decoder, fieldType, depth+1); err != nil {
				return fmt.Errorf("field %q: %w", key, err)
			}
		}
	case '[':
		var elementType reflect.Type
		if typ != nil && (typ.Kind() == reflect.Array || typ.Kind() == reflect.Slice) {
			elementType = typ.Elem()
		}
		for decoder.More() {
			if err := scanJSON(decoder, elementType, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = decoder.Token()
	return err
}
