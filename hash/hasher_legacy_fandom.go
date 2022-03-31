package hash

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"

	"github.com/ory/kratos/driver/config"
)

var (
	fandomLegacyPrefix = []byte("legacyfandom")
	isFandomLegacyHash = regexp.MustCompile(`^\$legacyfandom\$`)

	ErrLegacyFandomUnknownSubType = fmt.Errorf("unknown fandom hash subtype")
	ErrLegacyFandomBadHashFormat  = fmt.Errorf("unknown fandom hash format")
	ErrLegacyFandomWrongHash      = fmt.Errorf("bad fandom hash")
	ErrEmptyHashCompare           = fmt.Errorf("empty hash provided")
	ErrEmptyPasswordCompare       = fmt.Errorf("empty password provided")
	ErrUnknownHashFormat          = fmt.Errorf("unknown hash format")

	legacyFandomOldPrefixWithSalt    = []byte("B")
	legacyFandomOldPrefixWithoutSalt = []byte("A")
	legacyFandomHashTypeBcrypt       = []byte("bcrypt")
	legacyFandomHashTypeWrapped      = []byte("wrapped")
)

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
		fandomLegacyPrefix,
		encoded,
	); err != nil {
		return nil, errors.WithStack(err)
	}

	return b.Bytes(), nil
}

func IsFandomLegacyHash(hash []byte) bool {
	return isFandomLegacyHash.Match(hash)
}

func (h *LegacyFandomCrypt) Understands(hash []byte) bool {
	return IsFandomLegacyHash(hash)
}

//CompareLegacyFandom will try to compare password against Fandom's legacy password hash
func CompareLegacyFandom(_ context.Context, cfg *config.Config, identityId uuid.UUID, password, hash []byte) error {
	if len(hash) == 0 {
		return errors.WithStack(ErrEmptyHashCompare)
	}
	if len(password) == 0 {
		return errors.WithStack(ErrEmptyPasswordCompare)
	}

	parts := bytes.SplitN(hash, []byte("$"), 3)
	if len(parts) != 3 {
		return errors.WithStack(ErrUnknownHashFormat)
	}

	if !bytes.Equal(parts[1], fandomLegacyPrefix) {
		return errors.WithStack(ErrUnknownHashAlgorithm)
	}

	decoded := make([]byte, hex.DecodedLen(len(parts[2])))
	_, err := hex.Decode(decoded, parts[2])
	if err != nil {
		return errors.WithStack(err)
	}

	var lastError error
	var aesDecrypted []byte
	hasherCfg, err := cfg.HasherLegacyFandom()
	if err != nil {
		return errors.WithStack(err)
	}
	for i := range hasherCfg.Key {
		aesDecrypted, lastError = aes256Decrypt(decoded[:], &hasherCfg.Key[i])
		if lastError == nil {
			break
		}
	}

	if lastError != nil {
		return errors.WithStack(lastError)
	}

	splited := bytes.Split(aesDecrypted, []byte(":"))
	if len(splited) < 3 {
		return errors.WithStack(ErrLegacyFandomBadHashFormat)
	}

	switch {
	case bytes.Equal(splited[1], legacyFandomHashTypeBcrypt):
		if err = fandomCompareBcrypt(password, splited[2]); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case bytes.Equal(splited[1], legacyFandomHashTypeWrapped):
		hash, oldHash, err := prepareHashToCompare(splited[2:], identityId, password)
		if err != nil {
			return errors.WithStack(err)
		}
		if err = fandomCompareBcrypt(oldHash, hash); err != nil {
			return errors.WithStack(err)
		}
		return nil
	default:
		return errors.WithStack(ErrLegacyFandomUnknownSubType)
	}
}

func sha512Hash(password []byte) []byte {
	hash := sha3.New512()
	_, _ = hash.Write(password)
	return hash.Sum(nil)
}

func fandomCompareBcrypt(password, hash []byte) error {
	sha512 := sha512Hash(password)
	return bcrypt.CompareHashAndPassword(hash, sha512)
}

func prepareHashToCompare(splitHash [][]byte, identityId uuid.UUID, password []byte) (part, salted []byte, err error) {
	// 3 types of old hash
	if bytes.Equal(splitHash[0], legacyFandomOldPrefixWithSalt) { // Type B
		if len(splitHash) < 3 {
			return nil, nil, ErrLegacyFandomWrongHash
		}
		return splitHash[2], md5HashPasswordWithSalt(password, splitHash[1]), nil
	}
	if bytes.Equal(splitHash[0], legacyFandomOldPrefixWithoutSalt) { // Type A
		if len(splitHash) < 2 {
			return nil, nil, ErrLegacyFandomWrongHash
		}
		return splitHash[1], md5HashPassword(password), nil
	}

	userId, err := getCommunityPlatformUserId(identityId)
	if err != nil {
		return nil, nil, err
	}
	log.Default().Printf("Generating legacy hash for identity: %s", identityId.String())
	return splitHash[0], md5HashPasswordWithSalt(password, []byte(userId)), nil
}

type SingleMapping struct {
	IdentityId *string `json:"identityId,omitempty"`
	UserId     *string `json:"userId,omitempty"`
}

func getCommunityPlatformUserId(identityId uuid.UUID) (userId string, err error) {
	// Allows overriding a service path for local setup
	serviceUrl, isConfigured := os.LookupEnv("IDENTITY_MAPPER_URL")
	if !isConfigured {
		log.Default().Printf("identity-mapper url is not configured")
		return "", fmt.Errorf("identity-mapper url is not configured")
	}
	req, err := retryablehttp.NewRequest("GET", serviceUrl+"/mapping/app/community_platform/identity/"+identityId.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wikia-Internal-Request", "1")

	client := retryablehttp.NewClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			err = closeErr
		}
	}(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("identity-mapper call failed with response code %v", resp.StatusCode)
	}
	if resp == nil {
		return "", fmt.Errorf("empty response provided from identity-mapper")
	}

	mapping := new(SingleMapping)
	err = json.NewDecoder(resp.Body).Decode(&mapping)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode identity-mapper response")
	}
	return *mapping.UserId, nil
}

func md5HashPasswordWithSalt(password, salt []byte) []byte {
	hasher := md5.New() // #nosec
	_, _ = hasher.Write(password)
	hash := hex.EncodeToString(hasher.Sum(nil))

	hash = fmt.Sprintf("%s-%s", salt, hash)

	hasher.Reset()
	_, _ = hasher.Write([]byte(hash))
	md5Hash := hasher.Sum(nil)
	result := make([]byte, hex.EncodedLen(len(md5Hash)))
	hex.Encode(result, md5Hash)

	return result
}

func md5HashPassword(password []byte) []byte {
	hasher := md5.New() // #nosec
	_, _ = hasher.Write(password)
	md5Hash := hasher.Sum(nil)
	result := make([]byte, hex.EncodedLen(len(md5Hash)))
	hex.Encode(result, md5Hash)

	return result
}

// aes256Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func aes256Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}
