package identity

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/jsonschema/v3"
	"github.com/ory/x/sqlxx"

	"github.com/ory/kratos/schema"
)

type SchemaExtensionCredentials struct {
	i *Identity
	v []string
	l sync.Mutex
	// fandom-start
	caseSensitiveIds bool
	// fandom-end
}

func NewSchemaExtensionCredentials(i *Identity, caseSensitiveIds bool) *SchemaExtensionCredentials {
	return &SchemaExtensionCredentials{i: i, caseSensitiveIds: caseSensitiveIds}
}

func (r *SchemaExtensionCredentials) setIdentifier(ct CredentialsType, value interface{}) {
	cred, ok := r.i.GetCredentials(ct)
	if !ok {
		cred = &Credentials{
			Type:        ct,
			Identifiers: []string{},
			Config:      sqlxx.JSONRawMessage{},
		}
	}

	// fandom-start
	var id string
	if !r.caseSensitiveIds {
		id = strings.ToLower(fmt.Sprintf("%s", value))
	} else {
		id = fmt.Sprintf("%s", value)
	}
	// fandom-end

	r.v = stringslice.Unique(append(r.v, id))
	cred.Identifiers = r.v
	r.i.SetCredentials(ct, *cred)

}

func (r *SchemaExtensionCredentials) Run(_ jsonschema.ValidationContext, s schema.ExtensionConfig, value interface{}) error {
	r.l.Lock()
	defer r.l.Unlock()

	if s.Credentials.Password.Identifier {
		r.setIdentifier(CredentialsTypePassword, value)
	}

	if s.Credentials.WebAuthn.Identifier {
		r.setIdentifier(CredentialsTypeWebAuthn, value)
	}

	return nil
}

func (r *SchemaExtensionCredentials) Finish() error {
	return nil
}
