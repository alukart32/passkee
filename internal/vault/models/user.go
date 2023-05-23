package models

// User represents the system user.
type User struct {
	ID       string
	Username []byte
	Password []byte
}

// IsEmpty checks on being empty.
func (u User) IsEmpty() bool {
	return len(u.Password) == 0 && len(u.Username) == 0
}
