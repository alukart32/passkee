package models

import (
	"fmt"
)

type Object struct {
	UserID string
	Typ    ObjectType
	Name   []byte
	Notes  []byte
	Data   []byte
}

type ObjectType struct {
	T string
}

func ObjectTypeFromString(t string) (ObjectType, error) {
	if len(t) == 0 {
		return UndefinedObjectType, fmt.Errorf("empty type")
	}

	switch t {
	case "text":
		return TextObjectType, nil
	case "bin":
		return BinObjectType, nil
	default:
		return UndefinedObjectType, fmt.Errorf("undefined type %v", t)
	}
}

func (t *ObjectType) String() string {
	return t.T
}

var (
	UndefinedObjectType = ObjectType{T: "undefined"}
	TextObjectType      = ObjectType{T: "text"}
	BinObjectType       = ObjectType{T: "bin"}
)
