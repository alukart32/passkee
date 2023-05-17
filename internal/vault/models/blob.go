package models

import (
	"fmt"
)

type Blob struct {
	Meta  BlobMeta
	Notes []byte
	Data  []byte
}

func (b *Blob) IsEmpty() bool {
	return b.Meta.IsEmpty() && len(b.Data) == 0
}

type BlobMeta struct {
	Obj ObjectMeta
	Typ BlobType
}

func (m *BlobMeta) IsEmpty() bool {
	return m.Obj.IsEmpty() && len(m.Typ.T) == 0
}

type BlobType struct {
	T string
}

func ObjectTypeFromString(t string) (BlobType, error) {
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

func (t *BlobType) String() string {
	return t.T
}

var (
	UndefinedObjectType = BlobType{T: "undefined"}
	TextObjectType      = BlobType{T: "text"}
	BinObjectType       = BlobType{T: "bin"}
)
