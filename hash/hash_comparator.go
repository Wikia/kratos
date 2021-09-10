package hash

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"

	"github.com/ory/kratos/driver/config"
)

var ErrUnknownHashAlgorithm = errors.New("unknown hash algorithm")
var ErrUnknownHashFormat = fmt.Errorf("unknown hash format")
var ErrEmptyHashCompare = fmt.Errorf("empty hash provided")
var ErrEmptyPasswordCompare = fmt.Errorf("empty password provided")

var hashSeparator = []byte("$")
var bcryptLegacyPrefix = regexp.MustCompile(`^2[abzy]?$`)
//fandom-start - add param: identityId uuid.UUID
func Compare(ctx context.Context, cfg *config.Config, identityId uuid.UUID, password []byte, hash []byte) error {
//fandom-end
	algorithm, realHash, err := ParsePasswordHash(hash)
	if err != nil {
		return errors.WithStack(err)
	}

	switch {
	case bytes.Equal(algorithm, Argon2AlgorithmId):
		return CompareArgon2id(ctx, cfg, password, realHash)
	case bytes.Equal(algorithm, BcryptAlgorithmId):
		return CompareBcrypt(ctx, cfg, password, realHash)
	//fandom-start
	case bytes.Equal(algorithm, LegacyFandomHasherId):
		return CompareLegacyFandom(ctx, cfg, identityId, password, realHash)
	//fandom-end
	default:
		return ErrUnknownHashAlgorithm
	}
}

func CompareBcrypt(_ context.Context, _ *config.Config, password []byte, hash []byte) error {
	if err := validateBcryptPasswordLength(password); err != nil {
		return errors.WithStack(err)
	}

	err := bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func IsPasswordHash(hash []byte) bool {
	_, _, err := ParsePasswordHash(hash)
	return err == nil
}

func ParsePasswordHash(input []byte) (algorithm, hash []byte, err error) {
	hashParts := bytes.SplitN(input, hashSeparator, 3)
	if len(hashParts) != 3 {
		err = errors.WithStack(ErrUnknownHashFormat)
		return
	}

	hash = append(hashSeparator, hashParts[2]...)
	switch {
	case bytes.Equal(hashParts[1], Argon2AlgorithmId):
		algorithm = Argon2AlgorithmId
		return
	case bcryptLegacyPrefix.Match(hashParts[1]):
		hash = input
		fallthrough
	case bytes.Equal(hashParts[1], BcryptAlgorithmId):
		algorithm = BcryptAlgorithmId
		return
	//fandom-start
	case bytes.Equal(hashParts[1], LegacyFandomHasherId):
		algorithm = LegacyFandomHasherId
		return
	//fandom-end
	default:
		err = ErrUnknownHashAlgorithm
		return
	}
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

func CompareArgon2id(_ context.Context, _ *config.Config, password []byte, hashPart []byte) error {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeArgon2idHash(hashPart)
	if err != nil {
		return errors.WithStack(err)
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey(password, salt, p.Iterations, uint32(p.Memory), p.Parallelism, p.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}

func decodeArgon2idHash(encodedHash []byte) (p *config.Argon2, salt, hash []byte, err error) {
	parts := strings.Split(string(encodedHash), string(hashSeparator))
	if len(parts) != 5 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(parts[1], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = new(config.Argon2)
	_, err = fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

//fandom-start

var ErrLegacyFandomUnknownSubType = fmt.Errorf("unknown fandom hash subtype")
var ErrLegacyFandomBadHashFormat = fmt.Errorf("unknown fandom hash format")
var ErrLegacyFandomWrongHash = fmt.Errorf("bad fandom hash")
var legacyFandomOldPrefixWithSalt = []byte("B")
var legacyFandomOldPrefixWithoutSalt = []byte("A")
var legacyFandomHashTypeBcrypt = []byte("bcrypt")
var legacyFandomHashTypeWrapped = []byte("wrapped")

//CompareLegacyFandom will try to compare password against Fandom's legacy password hash
func CompareLegacyFandom(_ context.Context, cfg *config.Config, identityId uuid.UUID, password, hash []byte) error {
	if len(hash) == 0 {
		return errors.WithStack(ErrEmptyHashCompare)
	}
	if len(password) == 0 {
		return errors.WithStack(ErrEmptyPasswordCompare)
	}

	decoded := make([]byte, hex.DecodedLen(len(hash[1:])))
	_, err := hex.Decode(decoded, hash[1:])
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
	UserId *string `json:"userId,omitempty"`
}

func getCommunityPlatformUserId(identityId uuid.UUID) (userId string, err error) {
	// Allow to override service path for local setup
	serviceUrl, isConfigured := os.LookupEnv("IDENTITY_MAPPER_URL")
	if !isConfigured {
		serviceUrl = "http://identity-mapper"
	}
	req, err := retryablehttp.NewRequest("GET", serviceUrl + "/appId/community_platform/" + identityId.String(), []byte(""))
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
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("identity-mapper call failed with response code %v", resp.StatusCode)
	}
	if resp == nil {
		return "", fmt.Errorf("empty response provided from identity-mapper")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "could not read response body from identity-mapper")
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			err = closeErr
		}
	}(resp.Body)

	mapping := new(SingleMapping)
	if err = json.Unmarshal(body, &mapping); err != nil {
		return "", errors.Wrap(err, "identity-mapper response could not be unmarshalled properly")
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

//fandom-end
