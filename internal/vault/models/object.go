package models

// ObjectMeta defines the identification information of the object.
type ObjectMeta struct {
	UserID string
	Name   []byte
}

// IsEmpty checks on being empty.
func (m *ObjectMeta) IsEmpty() bool {
	return len(m.UserID) == 0 &&
		len(m.Name) == 0
}

// Password represents the password pair record.
type Password struct {
	Meta  ObjectMeta
	Data  []byte
	Notes []byte
}

// IsEmpty checks on being empty.
func (p *Password) IsEmpty() bool {
	return p.Meta.IsEmpty() && len(p.Data) == 0
}

// CreditCard represents the credit card record.
type CreditCard struct {
	Meta  ObjectMeta
	Data  []byte
	Notes []byte
}

// IsEmpty checks on being empty.
func (c *CreditCard) IsEmpty() bool {
	return c.Meta.IsEmpty() && len(c.Data) == 0
}
