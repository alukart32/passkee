package models

type User struct {
	ID       string
	Username []byte
	Password []byte
}

func (u User) IsEmpty() bool {
	return len(u.Password) == 0 && len(u.Username) == 0
}
