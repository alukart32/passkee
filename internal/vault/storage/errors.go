package storage

import "errors"

// Record name unique violation.
var ErrNameUniqueViolation = errors.New("record name not unique")
