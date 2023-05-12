package models

type Passwords struct {
	UserID string
	Name   []byte
	Data   []byte
	Notes  []byte
}

func (p *Passwords) IsEmpty() bool {
	return len(p.UserID) == 0 &&
		len(p.Name) == 0 &&
		len(p.Data) == 0
}
