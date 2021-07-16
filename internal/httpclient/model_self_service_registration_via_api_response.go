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

// SelfServiceRegistrationViaApiResponse The Response for Registration Flows via API
type SelfServiceRegistrationViaApiResponse struct {
	Identity Identity `json:"identity"`
	Session  *Session `json:"session,omitempty"`
	// The Session Token  This field is only set when the session hook is configured as a post-registration hook.  A session token is equivalent to a session cookie, but it can be sent in the HTTP Authorization Header:  Authorization: bearer ${session-token}  The session token is only issued for API flows, not for Browser flows!
	SessionToken *string `json:"session_token,omitempty"`
}

// NewSelfServiceRegistrationViaApiResponse instantiates a new SelfServiceRegistrationViaApiResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSelfServiceRegistrationViaApiResponse(identity Identity) *SelfServiceRegistrationViaApiResponse {
	this := SelfServiceRegistrationViaApiResponse{}
	this.Identity = identity
	return &this
}

// NewSelfServiceRegistrationViaApiResponseWithDefaults instantiates a new SelfServiceRegistrationViaApiResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSelfServiceRegistrationViaApiResponseWithDefaults() *SelfServiceRegistrationViaApiResponse {
	this := SelfServiceRegistrationViaApiResponse{}
	return &this
}

// GetIdentity returns the Identity field value
func (o *SelfServiceRegistrationViaApiResponse) GetIdentity() Identity {
	if o == nil {
		var ret Identity
		return ret
	}

	return o.Identity
}

// GetIdentityOk returns a tuple with the Identity field value
// and a boolean to check if the value has been set.
func (o *SelfServiceRegistrationViaApiResponse) GetIdentityOk() (*Identity, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Identity, true
}

// SetIdentity sets field value
func (o *SelfServiceRegistrationViaApiResponse) SetIdentity(v Identity) {
	o.Identity = v
}

// GetSession returns the Session field value if set, zero value otherwise.
func (o *SelfServiceRegistrationViaApiResponse) GetSession() Session {
	if o == nil || o.Session == nil {
		var ret Session
		return ret
	}
	return *o.Session
}

// GetSessionOk returns a tuple with the Session field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SelfServiceRegistrationViaApiResponse) GetSessionOk() (*Session, bool) {
	if o == nil || o.Session == nil {
		return nil, false
	}
	return o.Session, true
}

// HasSession returns a boolean if a field has been set.
func (o *SelfServiceRegistrationViaApiResponse) HasSession() bool {
	if o != nil && o.Session != nil {
		return true
	}

	return false
}

// SetSession gets a reference to the given Session and assigns it to the Session field.
func (o *SelfServiceRegistrationViaApiResponse) SetSession(v Session) {
	o.Session = &v
}

// GetSessionToken returns the SessionToken field value if set, zero value otherwise.
func (o *SelfServiceRegistrationViaApiResponse) GetSessionToken() string {
	if o == nil || o.SessionToken == nil {
		var ret string
		return ret
	}
	return *o.SessionToken
}

// GetSessionTokenOk returns a tuple with the SessionToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SelfServiceRegistrationViaApiResponse) GetSessionTokenOk() (*string, bool) {
	if o == nil || o.SessionToken == nil {
		return nil, false
	}
	return o.SessionToken, true
}

// HasSessionToken returns a boolean if a field has been set.
func (o *SelfServiceRegistrationViaApiResponse) HasSessionToken() bool {
	if o != nil && o.SessionToken != nil {
		return true
	}

	return false
}

// SetSessionToken gets a reference to the given string and assigns it to the SessionToken field.
func (o *SelfServiceRegistrationViaApiResponse) SetSessionToken(v string) {
	o.SessionToken = &v
}

func (o SelfServiceRegistrationViaApiResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["identity"] = o.Identity
	}
	if o.Session != nil {
		toSerialize["session"] = o.Session
	}
	if o.SessionToken != nil {
		toSerialize["session_token"] = o.SessionToken
	}
	return json.Marshal(toSerialize)
}

type NullableSelfServiceRegistrationViaApiResponse struct {
	value *SelfServiceRegistrationViaApiResponse
	isSet bool
}

func (v NullableSelfServiceRegistrationViaApiResponse) Get() *SelfServiceRegistrationViaApiResponse {
	return v.value
}

func (v *NullableSelfServiceRegistrationViaApiResponse) Set(val *SelfServiceRegistrationViaApiResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableSelfServiceRegistrationViaApiResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableSelfServiceRegistrationViaApiResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSelfServiceRegistrationViaApiResponse(val *SelfServiceRegistrationViaApiResponse) *NullableSelfServiceRegistrationViaApiResponse {
	return &NullableSelfServiceRegistrationViaApiResponse{value: val, isSet: true}
}

func (v NullableSelfServiceRegistrationViaApiResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSelfServiceRegistrationViaApiResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
