package models

type Password struct {
	UserID string
	Name   []byte
	Data   []byte
	Notes  []byte
}

func (p *Password) IsEmpty() bool {
	return len(p.UserID) == 0 &&
		len(p.Name) == 0 &&
		len(p.Data) == 0
}
