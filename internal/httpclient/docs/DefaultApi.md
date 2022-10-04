# \DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**V0alpha2**](DefaultApi.md#V0alpha2) | **Get** /admin/token/extend | Calling this endpoint refreshes a current user session. If &#x60;session.refresh_min_time_left&#x60; is set it will only refresh the session after this time has passed.



## V0alpha2

> Session V0alpha2(ctx).Execute()

Calling this endpoint refreshes a current user session. If `session.refresh_min_time_left` is set it will only refresh the session after this time has passed.



### Example

```go
package main

import (
    "context"
    "fmt"
    "os"
    openapiclient "./openapi"
)

func main() {

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.DefaultApi.V0alpha2(context.Background()).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `DefaultApi.V0alpha2``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `V0alpha2`: Session
    fmt.Fprintf(os.Stdout, "Response from `DefaultApi.V0alpha2`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiV0alpha2Request struct via the builder pattern


### Return type

[**Session**](Session.md)

### Authorization

[oryAccessToken](../README.md#oryAccessToken)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

