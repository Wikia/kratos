package hash_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/internal"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"

	"github.com/ory/kratos/hash"
)

func TestComparatorLegacyFandomSuccess(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
		mkpw(t, 96),
		mkpw(t, 128),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			hasher := hash.NewHasherLegacyFandom(reg)

			hs, err := hasher.Generate(context.Background(), pw)

			assert.Nil(t, err)

			identityId, _ := uuid.NewV4()
			err = hash.CompareLegacyFandom(context.Background(), reg.Config(context.Background()), identityId, pw, hs)
			assert.Nil(t, err, "hash validation fails")
		})
	}
}

func TestComparatorLegacyFandomFail(t *testing.T) {
	p := config.MustNew(t, logrusx.New("", ""), os.Stderr,
		configx.WithConfigFiles("../driver/config/stub/.kratos.yaml"))

	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
		mkpw(t, 96),
		mkpw(t, 128),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			mod := make([]byte, len(pw))
			copy(mod, pw)
			mod[len(pw)-1] = ^mod[len(pw)-1]

			identityId, _ := uuid.NewV4()
			err := hash.CompareLegacyFandom(context.Background(), p, identityId, pw, mod)
			assert.Error(t, err)
		})
	}
}

func TestLegacyFandomCompare(t *testing.T) {
	p := config.MustNew(t, logrusx.New("", ""), os.Stderr,
		configx.WithConfigFiles("../driver/config/stub/.kratos.yaml"))

	for _, testData := range [][3][]byte{
		// test bcrypt-aes hash
		{
			[]byte("$legacyfandom$49628e249027aefdd8be744defa08f87a0076dafb696257a2e3bc6b58c6dad643848a01434f0ef71113a56f2878fcaf9d144f057b41d135dd35313b20dd23efc3d539c575cfd76cc6e62936d48812a962a3b792dbddc8ebe1c8255dde3fdd5fe"),
			[]byte("$legacyfandom$49628e249027aefdd8be744defa08f87a0076dafb696257a2e3bc6b58c6dad643848a01434f0ef71113a56f2878fcaf9d144f057b41d135dd35313b20dd23efc3d539c575cfd76cc6e62936d48812a962a3b792dbddc8ebe1c8255dde3fdd5fe"),
			[]byte("$legacyfandom$49628e249027aefdd8be744defa08f87a0076dafb696257a2e3bc6b58c6dad643848a01434f0ef71113a56f2878fcaf9d144f057b41d135dd35313b20dd23efc3d539c575cfd76cc6e62936d48812a962a3b792dbddc8ebe1c8255dde3fdd5ff"),
		},
		// test type A wrapped hash
		{
			[]byte("$legacyfandom$197c91daa8ab5c7b5d693cde3e92347d1e73bbec63c19a5877614e0fe31dab8829ded35c7fe483a38b1aa00b2059056e8b15137845ce88d0604e394b1d371cfd114564828c2c8f3a8445b87575c556b7503d91246a2b34695b5aaa69b6e902c810414b"),
			[]byte("$legacyfandom$197c91daa8ab5c7b5d693cde3e92347d1e73bbec63c19a5877614e0fe31dab8829ded35c7fe483a38b1aa00b2059056e8b15137845ce88d0604e394b1d371cfd114564828c2c8f3a8445b87575c556b7503d91246a2b34695b5aaa69b6e902c810414b"),
			[]byte("$legacyfandom$197c91daa8ab5c7b5d693cde3e92347d1e73bbec63c19a5877614e0fe31dab8829ded35c7fe483a38b1aa00b2059056e8b15137845ce88d0604e394b1d371cfd114564828c2c8f3a8445b87575c556b7503d91246a2b34695b5aaa69b6e902c810414c"),
		},
		// test type B wrapped hash
		{
			[]byte("$legacyfandom$8eebdbf2e66c2e4c7935b5244907c1b25e87b3a9247c678e88d2c484ddf2ead10e4b32c5a84aad8bfe87e72a85c65db0e00fd34df27352ea578903533ed422c663ca61f139c8aa647b2ca12a4b2a274835262539f1b5e7166bf615ee61be9ec177c6f6caf0ce3369adeb1901"),
			[]byte("$legacyfandom$8eebdbf2e66c2e4c7935b5244907c1b25e87b3a9247c678e88d2c484ddf2ead10e4b32c5a84aad8bfe87e72a85c65db0e00fd34df27352ea578903533ed422c663ca61f139c8aa647b2ca12a4b2a274835262539f1b5e7166bf615ee61be9ec177c6f6caf0ce3369adeb1901"),
			[]byte("$legacyfandom$8eebdbf2e66c2e4c7935b5244907c1b25e87b3a9247c678e88d2c484ddf2ead10e4b32c5a84aad8bfe87e72a85c65db0e00fd34df27352ea578903533ed422c663ca61f139c8aa647b2ca12a4b2a274835262539f1b5e7166bf615ee61be9ec177c6f6caf0ce3369adeb1902"),
		},
	} {
		identityId, _ := uuid.NewV4()
		assert.Nil(t, hash.Compare(context.Background(), p, identityId, []byte("test"), testData[0]))
		assert.Nil(t, hash.CompareLegacyFandom(context.Background(), p, identityId, []byte("test"), testData[1]))
		assert.Error(t, hash.Compare(context.Background(), p, identityId, []byte("test"), testData[2]))
	}
}
