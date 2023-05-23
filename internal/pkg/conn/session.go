// The conn package provides basic client-server communication objects.
package conn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/aesgcm"
	"github.com/google/uuid"
)

// Info is the metadata of a connection to a remote server.
type Info struct {
	RemoteAddr string
	Creds      string // username:password in base64 format.
}

// Session represents a communication session between the client and the server.
// Messages within the session are encrypted with the AES-GCM algorithm.
type Session struct {
	Id  string
	key []byte // 32 bytes
}

// NewSession creates a new Session object.
func NewSession() (Session, error) {
	key, err := genPrivateKey(32)
	if err != nil {
		return Session{}, fmt.Errorf("can't generate a new session key")
	}
	return Session{
		Id:  uuid.New().String(),
		key: key,
	}, nil
}

// SessionFrom creates a new Session object with known id and key values.
func SessionFrom(id string, key []byte) (Session, error) {
	if len(id) == 0 {
		return Session{}, fmt.Errorf("unexpected empty id")
	}
	if len(key) == 0 {
		return Session{}, fmt.Errorf("unexpected empty key")
	}

	return Session{
		Id:  id,
		key: key,
	}, nil
}

// Base64Key returns the encryption key in Base64 format.
func (s *Session) Base64Key() string {
	return base64.StdEncoding.EncodeToString([]byte(s.key))
}

// DataEncrypter creates a new DataEncrypter based on the current key.
// By default, the AES-GCM is used.
func (s *Session) DataEncrypter() (DataEncrypter, error) {
	gcmKey, err := aesgcm.Encrypter(s.key)
	if err != nil {
		return nil, fmt.Errorf("can't create a new encryption key: %v", err)
	}
	return gcmKey, nil
}

// DataEncrypter defines the interface for the session message encryptor.
type DataEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

// genPrivateKey generates a secret key of dimension n.
func genPrivateKey(n int) ([]byte, error) {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
