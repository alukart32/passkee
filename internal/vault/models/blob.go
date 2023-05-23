package models

import (
	"fmt"
)

// Blob represents the binary object record.
type Blob struct {
	Meta  BlobMeta
	Notes []byte
	Data  []byte
}

// IsEmpty checks on being empty.
func (b *Blob) IsEmpty() bool {
	return b.Meta.IsEmpty() && len(b.Data) == 0
}

// BlobMeta represents the extra information of the Blob object.
type BlobMeta struct {
	Obj ObjectMeta
	Typ BlobType
}

// IsEmpty checks on being empty.
func (m *BlobMeta) IsEmpty() bool {
	return m.Obj.IsEmpty() && len(m.Typ.T) == 0
}

// BlobType defines Blob object type.
type BlobType struct {
	T string
}

func ObjectTypeFromString(t string) (BlobType, error) {
	if len(t) == 0 {
		return UndefinedObjectType, fmt.Errorf("empty type")
	}

	switch t {
	case "OBJECT_TEXT":
		return TextObjectType, nil
	case "OBJECT_BIN":
		return BinObjectType, nil
	default:
		return UndefinedObjectType, fmt.Errorf("undefined type %v", t)
	}
}

func (t *BlobType) String() string {
	return t.T
}

var (
	UndefinedObjectType = BlobType{T: "UNDEFINED"}
	TextObjectType      = BlobType{T: "TEXT"}
	BinObjectType       = BlobType{T: "BIN"}
)
