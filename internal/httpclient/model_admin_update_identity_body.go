/*
 * Ory Kratos API
 *
 * Documentation for all public and administrative Ory Kratos APIs. Public and administrative APIs are exposed on different ports. Public APIs can face the public internet without any protection while administrative APIs should never be exposed without prior authorization. To protect the administative API port you should use something like Nginx, Ory Oathkeeper, or any other technology capable of authorizing incoming requests.
 *
 * API version: 1.0.0
 * Contact: hi@ory.sh
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// AdminUpdateIdentityBody struct for AdminUpdateIdentityBody
type AdminUpdateIdentityBody struct {
	// Store metadata about the user which is only accessible through admin APIs such as `GET /admin/identities/<id>`.
	MetadataAdmin interface{} `json:"metadata_admin,omitempty"`
	// Store metadata about the identity which the identity itself can see when calling for example the session endpoint. Do not store sensitive information (e.g. credit score) about the identity in this field.
	MetadataPublic interface{} `json:"metadata_public,omitempty"`
	// SchemaID is the ID of the JSON Schema to be used for validating the identity's traits. If set will update the Identity's SchemaID.
	SchemaId string        `json:"schema_id"`
	State    IdentityState `json:"state"`
	// Traits represent an identity's traits. The identity is able to create, modify, and delete traits in a self-service manner. The input will always be validated against the JSON Schema defined in `schema_id`.
	Traits map[string]interface{} `json:"traits"`
}

// NewAdminUpdateIdentityBody instantiates a new AdminUpdateIdentityBody object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAdminUpdateIdentityBody(schemaId string, state IdentityState, traits map[string]interface{}) *AdminUpdateIdentityBody {
	this := AdminUpdateIdentityBody{}
	this.SchemaId = schemaId
	this.State = state
	this.Traits = traits
	return &this
}

// NewAdminUpdateIdentityBodyWithDefaults instantiates a new AdminUpdateIdentityBody object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAdminUpdateIdentityBodyWithDefaults() *AdminUpdateIdentityBody {
	this := AdminUpdateIdentityBody{}
	return &this
}

// GetMetadataAdmin returns the MetadataAdmin field value if set, zero value otherwise (both if not set or set to explicit null).
func (o *AdminUpdateIdentityBody) GetMetadataAdmin() interface{} {
	if o == nil {
		var ret interface{}
		return ret
	}
	return o.MetadataAdmin
}

// GetMetadataAdminOk returns a tuple with the MetadataAdmin field value if set, nil otherwise
// and a boolean to check if the value has been set.
// NOTE: If the value is an explicit nil, `nil, true` will be returned
func (o *AdminUpdateIdentityBody) GetMetadataAdminOk() (*interface{}, bool) {
	if o == nil || o.MetadataAdmin == nil {
		return nil, false
	}
	return &o.MetadataAdmin, true
}

// HasMetadataAdmin returns a boolean if a field has been set.
func (o *AdminUpdateIdentityBody) HasMetadataAdmin() bool {
	if o != nil && o.MetadataAdmin != nil {
		return true
	}

	return false
}

// SetMetadataAdmin gets a reference to the given interface{} and assigns it to the MetadataAdmin field.
func (o *AdminUpdateIdentityBody) SetMetadataAdmin(v interface{}) {
	o.MetadataAdmin = v
}

// GetMetadataPublic returns the MetadataPublic field value if set, zero value otherwise (both if not set or set to explicit null).
func (o *AdminUpdateIdentityBody) GetMetadataPublic() interface{} {
	if o == nil {
		var ret interface{}
		return ret
	}
	return o.MetadataPublic
}

// GetMetadataPublicOk returns a tuple with the MetadataPublic field value if set, nil otherwise
// and a boolean to check if the value has been set.
// NOTE: If the value is an explicit nil, `nil, true` will be returned
func (o *AdminUpdateIdentityBody) GetMetadataPublicOk() (*interface{}, bool) {
	if o == nil || o.MetadataPublic == nil {
		return nil, false
	}
	return &o.MetadataPublic, true
}

// HasMetadataPublic returns a boolean if a field has been set.
func (o *AdminUpdateIdentityBody) HasMetadataPublic() bool {
	if o != nil && o.MetadataPublic != nil {
		return true
	}

	return false
}

// SetMetadataPublic gets a reference to the given interface{} and assigns it to the MetadataPublic field.
func (o *AdminUpdateIdentityBody) SetMetadataPublic(v interface{}) {
	o.MetadataPublic = v
}

// GetSchemaId returns the SchemaId field value
func (o *AdminUpdateIdentityBody) GetSchemaId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.SchemaId
}

// GetSchemaIdOk returns a tuple with the SchemaId field value
// and a boolean to check if the value has been set.
func (o *AdminUpdateIdentityBody) GetSchemaIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SchemaId, true
}

// SetSchemaId sets field value
func (o *AdminUpdateIdentityBody) SetSchemaId(v string) {
	o.SchemaId = v
}

// GetState returns the State field value
func (o *AdminUpdateIdentityBody) GetState() IdentityState {
	if o == nil {
		var ret IdentityState
		return ret
	}

	return o.State
}

// GetStateOk returns a tuple with the State field value
// and a boolean to check if the value has been set.
func (o *AdminUpdateIdentityBody) GetStateOk() (*IdentityState, bool) {
	if o == nil {
		return nil, false
	}
	return &o.State, true
}

// SetState sets field value
func (o *AdminUpdateIdentityBody) SetState(v IdentityState) {
	o.State = v
}

// GetTraits returns the Traits field value
func (o *AdminUpdateIdentityBody) GetTraits() map[string]interface{} {
	if o == nil {
		var ret map[string]interface{}
		return ret
	}

	return o.Traits
}

// GetTraitsOk returns a tuple with the Traits field value
// and a boolean to check if the value has been set.
func (o *AdminUpdateIdentityBody) GetTraitsOk() (map[string]interface{}, bool) {
	if o == nil {
		return nil, false
	}
	return o.Traits, true
}

// SetTraits sets field value
func (o *AdminUpdateIdentityBody) SetTraits(v map[string]interface{}) {
	o.Traits = v
}

func (o AdminUpdateIdentityBody) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.MetadataAdmin != nil {
		toSerialize["metadata_admin"] = o.MetadataAdmin
	}
	if o.MetadataPublic != nil {
		toSerialize["metadata_public"] = o.MetadataPublic
	}
	if true {
		toSerialize["schema_id"] = o.SchemaId
	}
	if true {
		toSerialize["state"] = o.State
	}
	if true {
		toSerialize["traits"] = o.Traits
	}
	return json.Marshal(toSerialize)
}

type NullableAdminUpdateIdentityBody struct {
	value *AdminUpdateIdentityBody
	isSet bool
}

func (v NullableAdminUpdateIdentityBody) Get() *AdminUpdateIdentityBody {
	return v.value
}

func (v *NullableAdminUpdateIdentityBody) Set(val *AdminUpdateIdentityBody) {
	v.value = val
	v.isSet = true
}

func (v NullableAdminUpdateIdentityBody) IsSet() bool {
	return v.isSet
}

func (v *NullableAdminUpdateIdentityBody) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAdminUpdateIdentityBody(val *AdminUpdateIdentityBody) *NullableAdminUpdateIdentityBody {
	return &NullableAdminUpdateIdentityBody{value: val, isSet: true}
}

func (v NullableAdminUpdateIdentityBody) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAdminUpdateIdentityBody) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
