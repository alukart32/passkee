// Package session provides capabilities for managing connection sessions with the client.
package session

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/patrickmn/go-cache"
)

// manager is a manager for created sessions with the client.
type manager struct {
	// sessionID: base64 enc_key
	sessions *cache.Cache
}

// Manager returns a new session manager.
func Manager() *manager {
	return &manager{
		sessions: cache.New(cache.DefaultExpiration, 10*time.Minute),
	}
}

// InitSession creates a new session with the client.
func (m *manager) InitSession() (conn.Session, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return conn.Session{}, err
	}

	err = m.sessions.Add(sess.Id, sess.Base64Key(), cache.NoExpiration)
	if err != nil {
		return conn.Session{}, fmt.Errorf("can't save a new session: %v", err)
	}

	return sess, nil
}

// TerminateSession ends session by id.
func (m *manager) TerminateSession(id string) {
	m.sessions.Delete(id)
}

// SessionById returns session context by id.
func (m *manager) SessionById(id string) (conn.Session, error) {
	v, ok := m.sessions.Get(id)
	if !ok {
		return conn.Session{}, fmt.Errorf("can't find session by %v", id)
	}

	key, ok := v.(string)
	if !ok {
		return conn.Session{}, fmt.Errorf("can't unbox session key")
	}
	rawKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return conn.Session{}, fmt.Errorf("can't parse session key")
	}

	return conn.SessionFrom(id, rawKey)
}
