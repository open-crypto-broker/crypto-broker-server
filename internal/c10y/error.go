package c10y

import "errors"

// ErrMissingKeyConstraints is returned when key constraints are missing for a given algorithm
var ErrMissingKeyConstraints = errors.New("missing key constraints")
