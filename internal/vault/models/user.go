package models

type User struct {
	ID       string
	Login    []byte
	Password []byte
}

func (u User) IsEmpty() bool {
	return len(u.Password) == 0 && len(u.Login) == 0
}
