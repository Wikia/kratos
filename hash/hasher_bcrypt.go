package hash

import (
	"bytes"
	"context"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/schema"
)

const BcryptAlgorithmId = "bcrypt"

type Bcrypt struct {
	c BcryptConfiguration
}

type BcryptConfiguration interface {
	config.Provider
}

func NewHasherBcrypt(c BcryptConfiguration) *Bcrypt {
	return &Bcrypt{c: c}
}

func (h *Bcrypt) Generate(ctx context.Context, password []byte) ([]byte, error) {
	if err := validateBcryptPasswordLength(password); err != nil {
		return nil, errors.WithStack(err)
	}

	hash, err := bcrypt.GenerateFromPassword(password, int(h.c.Config(ctx).HasherBcrypt().Cost))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var b bytes.Buffer
	if _, err := fmt.Fprintf(
		&b,
		"$%s%s",
		BcryptAlgorithmId,
		hash,
	); err != nil {
		return nil, errors.WithStack(err)
	}

	return b.Bytes(), nil
}

func validateBcryptPasswordLength(password []byte) error {
	// Bcrypt truncates the password to the first 72 bytes, following the OpenBSD implementation,
	// so if password is longer than 72 bytes, function returns an error
	// See https://en.wikipedia.org/wiki/Bcrypt#User_input
	if len(password) > 72 {
		return schema.NewPasswordPolicyViolationError(
			"#/password",
			"passwords are limited to a maximum length of 72 characters",
		)
	}
	return nil
}
