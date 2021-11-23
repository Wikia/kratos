package hash

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"

	"github.com/ory/kratos/driver/config"
)

var LegacyFandomHasherId = []byte("legacyfandom")

type LegacyFandomCrypt struct {
	c LegacyFandomCryptConfiguration
}

type LegacyFandomCryptConfiguration interface {
	config.Provider
}

// aes256Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func aes256Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func NewHasherLegacyFandom(c LegacyFandomCryptConfiguration) *LegacyFandomCrypt {
	return &LegacyFandomCrypt{c: c}
}

func (h *LegacyFandomCrypt) Generate(ctx context.Context, password []byte) ([]byte, error) {
	cfg, err := h.c.Config(ctx).HasherLegacyFandom()
	if err != nil {
		return nil, errors.WithStack(err)
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

func (h *LegacyFandomCrypt) Understands(hash []byte) bool {
	algorithm, _, err := ParsePasswordHash(hash)
	return err == nil && bytes.Equal(algorithm, LegacyFandomHasherId)
}
