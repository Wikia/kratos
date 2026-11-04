// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"reflect"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/schema"
	"github.com/ory/x/jsonschemax"
)

// fandom-start

// ProtectedTraitPaths returns the paths (relative to the traits object) of all traits marked with
//
//	"ory.sh/kratos": {"protected": true}
//
// in the identity schema with the given ID.
func (v *Validator) ProtectedTraitPaths(ctx context.Context, schemaID string) ([]string, error) {
	ss, err := v.d.IdentityTraitsSchemas(ctx)
	if err != nil {
		return nil, err
	}

	s, err := ss.GetByID(schemaID)
	if err != nil {
		return nil, err
	}

	runner, err := schema.NewExtensionRunner(ctx)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	runner.Register(c)

	paths, err := jsonschemax.ListPathsWithArraysIncluded(ctx, s.URL.String()+"#/properties/traits", c)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, p := range paths {
		e, ok := p.CustomProperties[schema.ExtensionName].(*schema.ExtensionConfig)
		if !ok || !e.Protected {
			continue
		}
		// For array items (e.g. "emails.#") compare the whole array.
		result = append(result, strings.TrimSuffix(p.Name, ".#"))
	}

	return result, nil
}

// protectedTraitsModified returns true if any trait marked as protected in the identity schema differs between
// the original and the updated identity.
func (m *Manager) protectedTraitsModified(ctx context.Context, original, updated *Identity) (bool, error) {
	if reflect.DeepEqual(gjson.ParseBytes(original.Traits).Value(), gjson.ParseBytes(updated.Traits).Value()) {
		return false, nil
	}

	paths, err := m.r.IdentityValidator().ProtectedTraitPaths(ctx, updated.SchemaID)
	if err != nil {
		return false, err
	}

	for _, p := range paths {
		if !reflect.DeepEqual(
			gjson.GetBytes(original.Traits, p).Value(),
			gjson.GetBytes(updated.Traits, p).Value(),
		) {
			return true, nil
		}
	}

	return false, nil
}

// fandom-end
