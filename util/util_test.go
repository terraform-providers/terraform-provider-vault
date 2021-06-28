package util

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"reflect"
	"testing"
	"time"
)

type testingStruct struct {
	foobar bool
	list   []string
}

func TestExpiredTokenError(t *testing.T) {
	if ok := IsExpiredTokenErr(fmt.Errorf("error: invalid accessor custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("error: failed to find accessor entry custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(nil); ok {
		t.Errorf("Shouldn't be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("Error making request")); ok {
		t.Errorf("Shouldn't be expired")
	}
}

func TestSliceHasElement_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}

	found, index := SliceHasElement(slice, 2)
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceHasElement_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	found, index := SliceHasElement(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, testingStruct{foobar: false, list: []string{}})
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceAppendIfMissing_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expectedAppend := []interface{}{1, 2, 3, 4, 5, 6}

	append := SliceAppendIfMissing(slice, 3)
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, 6)
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceAppendIfMissing_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}
	expectedAppend := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	append := SliceAppendIfMissing(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceRemoveIfPresent_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expected := []interface{}{1, 2, 5, 4}

	removed := SliceRemoveIfPresent(slice, 10)
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, 3)
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}

	empty := make([]interface{}, 0)
	if len(SliceRemoveIfPresent(empty, 0)) != 0 {
		t.Errorf("Slice should be empty")
	}

	single := []interface{}{1}
	if len(SliceRemoveIfPresent(single, 1)) != 0 {
		t.Errorf("Slice should be empty")
	}
}

func TestSliceRemoveIfPresent_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}
	expected := []interface{}{
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}

	removed := SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{}})
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}
}

func TestParsePath(t *testing.T) {
	testCases := []struct {
		inputUserSuppliedPath, inputEndpoint string
		inputData                            *schema.ResourceData
		expected                             string
	}{
		{
			inputUserSuppliedPath: "my/transform/hello",
			inputEndpoint:         "/transform/role/{name}",
			inputData: schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"name": {Type: schema.TypeString},
			}, map[string]interface{}{
				"name": "foo",
			}),
			expected: "/my/transform/hello/role/foo",
		},
		{
			inputUserSuppliedPath: "jwt-1914071788362821795",
			inputEndpoint:         "/auth/jwt/config",
			inputData:             &schema.ResourceData{},
			expected:              "/auth/jwt-1914071788362821795/config",
		},
		{
			inputUserSuppliedPath: "accounting-transit",
			inputEndpoint:         "/transit/export/{type}/{name}/{version}",
			inputData: schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"name":    {Type: schema.TypeString},
				"type":    {Type: schema.TypeString},
				"version": {Type: schema.TypeString},
			}, map[string]interface{}{
				"version": "1",
				"type":    "encryption-key",
				"name":    "my-key",
			}),
			expected: "/accounting-transit/export/encryption-key/my-key/1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.inputUserSuppliedPath, func(t *testing.T) {
			actual := ParsePath(testCase.inputUserSuppliedPath, testCase.inputEndpoint, testCase.inputData)
			if actual != testCase.expected {
				t.Fatalf("expected %q, received %q", testCase.expected, actual)
			}
		})
	}
}

func TestPathParameters(t *testing.T) {
	testCases := []struct {
		endpoint, vaultPath string
		expected            map[string]string
	}{
		{
			endpoint:  "/transform/role/{name}",
			vaultPath: "/transform-56614161/foo7306072804/role/test-role-54539268/foo87766695434",
			expected: map[string]string{
				"path": "transform-56614161/foo7306072804",
				"name": "test-role-54539268/foo87766695434",
			},
		},
		{
			endpoint:  "/transit/sign/{name}/{urlalgorithm}",
			vaultPath: "/transit/sign/my-key/sha2-512",
			expected: map[string]string{
				"path":         "transit",
				"name":         "my-key",
				"urlalgorithm": "sha2-512",
			},
		},
		{
			endpoint:  "/transit/sign/{name}/{urlalgorithm}",
			vaultPath: "/my-transit/sign/my-key/sha2-512",
			expected: map[string]string{
				"path":         "my-transit",
				"name":         "my-key",
				"urlalgorithm": "sha2-512",
			},
		},
		{
			endpoint:  "/auth/approle/tidy/secret-id",
			vaultPath: "/auth/my-approle/tidy/secret-id",
			expected: map[string]string{
				"path": "my-approle",
			},
		},
		{
			endpoint:  "/sys/mfa/method/totp/{name}/admin-generate",
			vaultPath: "/sys/mfa/method/totp/my_totp/admin-generate",
			expected: map[string]string{
				"path": "sys",
				"name": "my_totp",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.endpoint, func(t *testing.T) {
			result, err := PathParameters(testCase.endpoint, testCase.vaultPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result, testCase.expected) {
				t.Fatalf("expected %+v but received %+v", testCase.expected, result)
			}
		})
	}
}

func TestParseDurationSecond(t *testing.T) {
	tests := map[string]struct {
		in      interface{}
		want    time.Duration
		wantErr bool
	}{
		"valid duration": {
			in:   "1m",
			want: 60 * time.Second,
		},
		"valid string number": {
			in:   "2",
			want: 2 * time.Second,
		},
		"empty string": {
			in:   "",
			want: time.Duration(0),
		},
		"invalid input": {
			in:      "foobar",
			wantErr: true,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			got, err := ParseDurationSecond(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDurationSecond() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseDurationSecond() got = %v, want %v", got, tt.want)
			}
		})
	}
}
