package models

type CreditCard struct {
	UserID string
	Name   []byte
	Data   []byte
	Notes  []byte
}

func (c *CreditCard) IsEmpty() bool {
	return len(c.UserID) == 0 &&
		len(c.Name) == 0 &&
		len(c.Data) == 0
}
