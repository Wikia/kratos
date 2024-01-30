/*
 * Ory Identities API
 *
 * This is the API specification for Ory Identities with features such as registration, login, recovery, account verification, profile settings, password reset, identity management, session management, email and sms delivery, and more.
 *
 * API version:
 * Contact: office@ory.sh
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// NeedsPrivilegedSessionError struct for NeedsPrivilegedSessionError
type NeedsPrivilegedSessionError struct {
	Error *GenericError `json:"error,omitempty"`
	// Points to where to redirect the user to next.
	RedirectBrowserTo string `json:"redirect_browser_to"`
}

// NewNeedsPrivilegedSessionError instantiates a new NeedsPrivilegedSessionError object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewNeedsPrivilegedSessionError(redirectBrowserTo string) *NeedsPrivilegedSessionError {
	this := NeedsPrivilegedSessionError{}
	this.RedirectBrowserTo = redirectBrowserTo
	return &this
}

// NewNeedsPrivilegedSessionErrorWithDefaults instantiates a new NeedsPrivilegedSessionError object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewNeedsPrivilegedSessionErrorWithDefaults() *NeedsPrivilegedSessionError {
	this := NeedsPrivilegedSessionError{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *NeedsPrivilegedSessionError) GetError() GenericError {
	if o == nil || o.Error == nil {
		var ret GenericError
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *NeedsPrivilegedSessionError) GetErrorOk() (*GenericError, bool) {
	if o == nil || o.Error == nil {
		return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *NeedsPrivilegedSessionError) HasError() bool {
	if o != nil && o.Error != nil {
		return true
	}

	return false
}

// SetError gets a reference to the given GenericError and assigns it to the Error field.
func (o *NeedsPrivilegedSessionError) SetError(v GenericError) {
	o.Error = &v
}

// GetRedirectBrowserTo returns the RedirectBrowserTo field value
func (o *NeedsPrivilegedSessionError) GetRedirectBrowserTo() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RedirectBrowserTo
}

// GetRedirectBrowserToOk returns a tuple with the RedirectBrowserTo field value
// and a boolean to check if the value has been set.
func (o *NeedsPrivilegedSessionError) GetRedirectBrowserToOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.RedirectBrowserTo, true
}

// SetRedirectBrowserTo sets field value
func (o *NeedsPrivilegedSessionError) SetRedirectBrowserTo(v string) {
	o.RedirectBrowserTo = v
}

func (o NeedsPrivilegedSessionError) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Error != nil {
		toSerialize["error"] = o.Error
	}
	if true {
		toSerialize["redirect_browser_to"] = o.RedirectBrowserTo
	}
	return json.Marshal(toSerialize)
}

type NullableNeedsPrivilegedSessionError struct {
	value *NeedsPrivilegedSessionError
	isSet bool
}

func (v NullableNeedsPrivilegedSessionError) Get() *NeedsPrivilegedSessionError {
	return v.value
}

func (v *NullableNeedsPrivilegedSessionError) Set(val *NeedsPrivilegedSessionError) {
	v.value = val
	v.isSet = true
}

func (v NullableNeedsPrivilegedSessionError) IsSet() bool {
	return v.isSet
}

func (v *NullableNeedsPrivilegedSessionError) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableNeedsPrivilegedSessionError(val *NeedsPrivilegedSessionError) *NullableNeedsPrivilegedSessionError {
	return &NullableNeedsPrivilegedSessionError{value: val, isSet: true}
}

func (v NullableNeedsPrivilegedSessionError) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableNeedsPrivilegedSessionError) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
