package hash_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"

	"github.com/ory/kratos/hash"
	"github.com/ory/kratos/internal"
)

func mkpw(t *testing.T, length int) []byte {
	pw := make([]byte, length)
	_, err := rand.Read(pw)
	require.NoError(t, err)
	return pw
}

func TestArgonHasher(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 128),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			for kk, h := range []hash.Hasher{
				hash.NewHasherArgon2(reg),
			} {
				t.Run(fmt.Sprintf("hasher=%T/password=%d", h, kk), func(t *testing.T) {
					hs, err := h.Generate(context.Background(), pw)
					require.NoError(t, err)
					assert.NotEqual(t, pw, hs)

					algorithm, realHash, err := hash.ParsePasswordHash(hs)
					assert.NoError(t, err)
					assert.Equal(t, hash.Argon2AlgorithmId, algorithm)

					require.NoError(t, hash.CompareArgon2id(context.Background(), reg.Config(context.Background()), pw, realHash))

					mod := make([]byte, len(pw))
					copy(mod, pw)
					mod[len(pw)-1] = ^pw[len(pw)-1]
					require.Error(t, hash.CompareArgon2id(context.Background(), reg.Config(context.Background()), mod, realHash))
				})
			}
		})
	}
}

func TestBcryptHasherGeneratesErrorWhenPasswordIsLong(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	hasher := hash.NewHasherBcrypt(reg)

	password := mkpw(t, 73)
	res, err := hasher.Generate(context.Background(), password)

	assert.Error(t, err, "password is too long")
	assert.Nil(t, res)
}

func TestBcryptHasherGeneratesHash(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			hasher := hash.NewHasherBcrypt(reg)
			hs, err := hasher.Generate(context.Background(), pw)

			assert.Nil(t, err)
			assert.True(t, hasher.Understands(hs))

			algorithm, realHash, err := hash.ParsePasswordHash(hs)
			assert.NoError(t, err)
			assert.Equal(t, hash.BcryptAlgorithmId, algorithm)

			// Valid format: $2a$12$[22 character salt][31 character hash]
			assert.Equal(t, 60, len(realHash), "invalid bcrypt hash length")
			assert.Equal(t, []byte("$2a$04$"), realHash[:7], "invalid bcrypt identifier")
		})
	}
}

func TestComparatorBcryptFailsWhenPasswordIsTooLong(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	password := mkpw(t, 73)
	err := hash.CompareBcrypt(context.Background(), reg.Config(context.Background()), password, []byte("hash"))

	assert.Error(t, err, "password is too long")
}

func TestComparatorBcryptSuccess(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			hasher := hash.NewHasherBcrypt(reg)

			hs, err := hasher.Generate(context.Background(), pw)

			assert.Nil(t, err)
			assert.True(t, hasher.Understands(hs))
			algorithm, realHash, err := hash.ParsePasswordHash(hs)
			assert.NoError(t, err)
			assert.Equal(t, hash.BcryptAlgorithmId, algorithm)

			err = hash.CompareBcrypt(context.Background(), reg.Config(context.Background()), pw, realHash)
			assert.Nil(t, err, "hash validation fails")
		})
	}
}

func TestComparatorBcryptFail(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			mod := make([]byte, len(pw))
			copy(mod, pw)
			mod[len(pw)-1] = ^pw[len(pw)-1]

			err := hash.CompareBcrypt(context.Background(), reg.Config(context.Background()), pw, mod)
			assert.Error(t, err)
		})
	}
}

func TestPbkdf2Hasher(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 128),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			for kk, hasher := range []hash.Hasher{
				&hash.Pbkdf2{
					Algorithm:  "sha1",
					Iterations: 100000,
					SaltLength: 32,
					KeyLength:  32,
				},
				&hash.Pbkdf2{
					Algorithm:  "sha224",
					Iterations: 100000,
					SaltLength: 32,
					KeyLength:  32,
				},
				&hash.Pbkdf2{
					Algorithm:  "sha256",
					Iterations: 100000,
					SaltLength: 32,
					KeyLength:  32,
				},
				&hash.Pbkdf2{
					Algorithm:  "sha384",
					Iterations: 100000,
					SaltLength: 32,
					KeyLength:  32,
				},
				&hash.Pbkdf2{
					Algorithm:  "sha512",
					Iterations: 100000,
					SaltLength: 32,
					KeyLength:  32,
				},
			} {
				t.Run(fmt.Sprintf("hasher=%T/password=%d", hasher, kk), func(t *testing.T) {
					_, reg := internal.NewFastRegistryWithMocks(t)
					hs, err := hasher.Generate(context.Background(), pw)
					require.NoError(t, err)
					assert.NotEqual(t, pw, hs)

					t.Logf("hash: %s", hs)
					require.NoError(t, hash.ComparePbkdf2(context.Background(), reg.Config(context.Background()), pw, hs))

					assert.True(t, hasher.Understands(hs))

					mod := make([]byte, len(pw))
					copy(mod, pw)
					mod[len(pw)-1] = ^pw[len(pw)-1]
					require.Error(t, hash.ComparePbkdf2(context.Background(), reg.Config(context.Background()), mod, hs))
				})
			}
		})
	}
}

func TestCompare(t *testing.T) {
	p := config.MustNew(t, logrusx.New("", ""), os.Stderr,
		configx.WithConfigFiles("../internal/.kratos.yaml"))

	identityId, _ := uuid.NewV4()

	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$unknown$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$bcrypt$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6")))
	assert.Nil(t, hash.CompareBcrypt(context.Background(), p, []byte("test"), []byte("$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$bcrypt$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL7")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$bcrypt$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Nil(t, hash.CompareBcrypt(context.Background(), p, []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$bcrypt$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZb1")))

	// legacy bcrypt hash format
	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Nil(t, hash.CompareBcrypt(context.Background(), p, []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZb1")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw")))
	assert.Nil(t, hash.CompareArgon2id(context.Background(), p, []byte("test"), []byte("$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRN2")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$argon2id$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp4")))
	assert.Nil(t, hash.CompareArgon2id(context.Background(), p, []byte("test"), []byte("$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp4")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$argon2id$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp5")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI")))
	assert.Nil(t, hash.ComparePbkdf2(context.Background(), p, []byte("test"), []byte("$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpp")))

	assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha512$i=100000,l=32$bdHBpn7OWOivJMVJypy2UqR0UnaD5prQXRZevj/05YU$+wArTfv1a+bNGO1iZrmEdVjhA+lL11wF4/IxpgYfPwc")))
	assert.Nil(t, hash.ComparePbkdf2(context.Background(), p, []byte("test"), []byte("$pbkdf2-sha512$i=100000,l=32$bdHBpn7OWOivJMVJypy2UqR0UnaD5prQXRZevj/05YU$+wArTfv1a+bNGO1iZrmEdVjhA+lL11wF4/IxpgYfPwc")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha512$i=100000,l=32$bdHBpn7OWOivJMVJypy2UqR0UnaD5prQXRZevj/05YU$+wArTfv1a+bNGO1iZrmEdVjhA+lL11wF4/IxpgYfPww")))

	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$aaaa$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXcc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpII")))
	assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), []byte("$pbkdf2-sha512$I=100000,l=32$bdHBpn7OWOivJMVJypy2UqR0UnaD5prQXRZevj/05YU$+wArTfv1a+bNGO1iZrmEdVjhA+lL11wF4/IxpgYfPwc")))
}
