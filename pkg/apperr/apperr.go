package apperr

import "fmt"

func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", op, err)
}

func New(op string) error {
	return fmt.Errorf("%s", op)
}
