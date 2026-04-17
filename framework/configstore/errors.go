package configstore

import (
	"errors"
	"fmt"
	"strings"
)

var ErrNotFound = errors.New("not found")
var ErrAlreadyExists = errors.New("already exists")

// ErrHasDependents is returned when a resource cannot be deleted because other
// resources still reference it (e.g., virtual keys attached to a customer).
type ErrHasDependents struct {
	Resource       string
	VirtualKeys    int
	Teams          int
	OtherResources map[string]int
}

func (e *ErrHasDependents) Error() string {
	parts := []string{}
	if e.VirtualKeys > 0 {
		parts = append(parts, fmt.Sprintf("%d virtual key(s)", e.VirtualKeys))
	}
	if e.Teams > 0 {
		parts = append(parts, fmt.Sprintf("%d team(s)", e.Teams))
	}
	for k, v := range e.OtherResources {
		if v > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", v, k))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "dependent resources")
	}
	return fmt.Sprintf("cannot delete %s: still referenced by %s", e.Resource, strings.Join(parts, ", "))
}

// ErrUnresolvedKeys is returned when one or more keys could not be resolved
type ErrUnresolvedKeys struct {
	Identifiers []string
}

func (e *ErrUnresolvedKeys) Error() string {
	return fmt.Sprintf("could not resolve keys: %s", strings.Join(e.Identifiers, ", "))
}
