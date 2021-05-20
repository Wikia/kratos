package hash

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ory/kratos/driver/config"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

var LegacyFandomHasherId = []byte("legacyfandom")

type LegacyFandomCrypt struct {
	c LegacyFandomCryptConfiguration
}

type LegacyFandomCryptConfiguration interface {
	config.Provider
}

func NewHasherLegacyFandom(c LegacyFandomCryptConfiguration) *LegacyFandomCrypt {
	return &LegacyFandomCrypt{c: c}
}

func (h *LegacyFandomCrypt) Generate(ctx context.Context, password []byte) ([]byte, error) {
	cfg := h.c.Config(ctx).HasherLegacyFandom()
	if len(cfg.Key) == 0 {
		return nil, NoAESKeyError
	}

	sh := sha3.New512()
	sh.Write(password)
	bcryptPassword, err := bcrypt.GenerateFromPassword(sh.Sum(nil), int(cfg.Cost))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bcryptPassword = append([]byte(":bcrypt:"), bcryptPassword...)
	hash, err := aes256Encrypt(bcryptPassword, &cfg.Key[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	encoded := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(encoded, hash[:])

	var b bytes.Buffer
	if _, err := fmt.Fprintf(
		&b,
		"$%s$%s",
		LegacyFandomHasherId,
		encoded,
	); err != nil {
		return nil, errors.WithStack(err)
	}

	return b.Bytes(), nil
}
