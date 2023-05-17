package models

type ObjectMeta struct {
	UserID string
	Name   []byte
}

func (m *ObjectMeta) IsEmpty() bool {
	return len(m.UserID) == 0 &&
		len(m.Name) == 0
}

type Password struct {
	Meta  ObjectMeta
	Data  []byte
	Notes []byte
}

func (p *Password) IsEmpty() bool {
	return p.Meta.IsEmpty() && len(p.Data) == 0
}

type CreditCard struct {
	Meta  ObjectMeta
	Data  []byte
	Notes []byte
}

func (c *CreditCard) IsEmpty() bool {
	return c.Meta.IsEmpty() && len(c.Data) == 0
}
