package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

const testCertificate = `
-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIJAIxJbvl6PnmvMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV
BAMTClZhdWx0IFRlc3QwHhcNMTgwNTA5MTcyMjU0WhcNMjgwNTA2MTcyMjU0WjAV
MRMwEQYDVQQDEwpWYXVsdCBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAxZj/1W69FiancHSEbMhfL0KZvftNksIN2rsMHhVkLDSn7KZyqlVhSOmy
gARFVmSwi5AO894FAuJU7L/RDcBD6mI3lTzDokeuRoRMpwbNg2aR+VNQaQpdHbLF
m3xTO1na7wuxO4F7tDzLQRKzO0wSmqBhXXdJsoTG97mA8Gq5tAR20Uz8vWh3PI8t
aFG6aSuL7rfm+O3iMoCPTj3DofUENfnd0ZxlXpR/X7Z1iQej5+jXIn0ygoXxc07r
fPd6J2jxz0lWL95Q65QWBSaKKNjWHaShSsqGe8KLZu9BFp20+M4Y8fd40B7+mlWk
17nUdqvwZtnNL1qf+t0SFFhueQY+4wIDAQABo3YwdDAdBgNVHQ4EFgQUoTWVof3Q
QakI0Xfamu5nJglXUwswRQYDVR0jBD4wPIAUoTWVof3QQakI0Xfamu5nJglXUwuh
GaQXMBUxEzARBgNVBAMTClZhdWx0IFRlc3SCCQCMSW75ej55rzAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQDFmMBq5s5vBHMrACXfgIBpZSSaiBXz8tVD
aiYO5UfZsWqEIn61+NrgJT4Xvhba3VZgGkOLX/9CfnTXx9nq4qL2ht4my2QszXXB
Jyi0pB+0VIQhbRzjbrYeQn8uCmN5DLph3sA+vJuUWvR7l6h1zUjzRrXWLFQ+qQxt
yYT18fgO3uttnbuzptDT23RDRySaoYLpeUFY47RIzFmuIO8bNsh8h5ymHNkVXrrv
vqDIxIPD/M21z4ZlZSbsokyVcsGKbF87xv8SFXj5GbtZ7UI0qVYr9zk/Y090Qv1a
ypM1k5jHWSBCixTrUFtWENQYLYhh2bMP1uJ4UMxSNJXCthRASqNF
-----END CERTIFICATE-----
`

const testKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxZj/1W69FiancHSEbMhfL0KZvftNksIN2rsMHhVkLDSn7KZy
qlVhSOmygARFVmSwi5AO894FAuJU7L/RDcBD6mI3lTzDokeuRoRMpwbNg2aR+VNQ
aQpdHbLFm3xTO1na7wuxO4F7tDzLQRKzO0wSmqBhXXdJsoTG97mA8Gq5tAR20Uz8
vWh3PI8taFG6aSuL7rfm+O3iMoCPTj3DofUENfnd0ZxlXpR/X7Z1iQej5+jXIn0y
goXxc07rfPd6J2jxz0lWL95Q65QWBSaKKNjWHaShSsqGe8KLZu9BFp20+M4Y8fd4
0B7+mlWk17nUdqvwZtnNL1qf+t0SFFhueQY+4wIDAQABAoIBAQCVeW/OXL7dCtCO
2RVz1P9sGM2EUZ4U7obcd7Jq73OfnRWKhz8mav/00BQfkxuAhxql+IvXHpRb4iqs
DU5vQIofu7ygQB8dm2vSHDKABz1fsS+rk8K4MwbNeHbTb/DmbMqZGhcwFHsnlPWM
fEDpElrgbYI52gr96EM7EjDfrVxdN83BLIHNki3OPDDMLAGkQV1wj6f9eNW/7QuU
Ryr9G7627mRi1tzu1W2ZfraiOY53TK6kDaa7tlxHYrh10O8lnblhfgkfQd6XIP09
IU52A6nZC+DifpM3S1NRl+WAXKzQsc/NR/6rrZB7so+5v7axHQLpGVoiRCUFcboS
5M5hnFhBAoGBAPUYgWTcu01CMrdCBZKm5UjAE6TKLYQrEF429HX81Q1UqO0c5ck0
KghUUtXCr/XGmsfPItbU4IlUutcpkd0DoKhTXLOvlshvtFUqVGa+HLQ3ZjyKJDCe
b+6RcYBFYjguQ6ToKvVbEMj9fkgWtOkwx8mcwxbFsTr2Nx20ZBUGYWiPAoGBAM5j
hOVddE21kbcrj3YKYwFykh7V+KgYMiAlm1lwDDLEKoEpZe6iCdE6/2eWgRHOtZgZ
qV7Pk69EdxSSI90N53CxDWvxs7xn4cvaX7tG8v5D/RJt8wToRwhBtSetvE6+ZxbO
Ov+I0j8mGYYVViIBQXNjc690NGhQlUSIxl1MQKZtAoGBAL3OcX5r1n15U49KCMjO
iOfzIANRMziUpQNhaaXp3BCLzJp785QC2r5ClzfFosEiQgGU7vUSPKT9wggYwEY5
pfRVQohA5fNpVm1R77T1a4NBF+KwVGB2glZtuklM8khxw5700Tfbgz8z2NT5CLdC
OKZwyUBcbukrffl6FruVimAPAoGAXw1YfGYxFUUFKi4GsV+RP25ru4XiMlCKbWHE
jUlcZNkRllDhoCjCirk4PZYENZZU7gsLhR3mr3bBvRidKcaoi68PNmKn26KgTElz
g4XmjZH0cNNwdBch97yDWRXbvwxT4B308BEse2bppGYZOCoJ4cGw2uKS7GQIivrP
GNLwh3UCgYBxkjgtvW3aH5/kdhEsggKFnmNPDkBGu1MDEEz5z+Z2w6jl18YyjgRj
HEjFCHzrCXzNp6fstSVLUXtvsbCtqTxj/XcBRkTMJqJBW9Xfh9nQbSKF6Hnudhle
bwvTJuiSbAHkhG+eM/04PpWPMo6skek10KmIBvGveHM8R89gbA1Fgw==
-----END RSA PRIVATE KEY-----
`

func TestCertAuthBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-cert-auth")
	name := acctest.RandomWithPrefix("tf-test-cert-name")

	allowedNames := []string{
		acctest.RandomWithPrefix("tf-ident-1"),
		acctest.RandomWithPrefix("tf-ident-2")}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_basic(backend, name, testCertificate, allowedNames),
				Check: resource.ComposeTestCheckFunc(
					testCertAuthBackendCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"name", name),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_ttl", "300"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_max_ttl", "600"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"allowed_names.#", "2"),
				),
			},
			{
				Config: testCertAuthBackendConfig_unset(backend, name, testCertificate, allowedNames),
				Check: resource.ComposeTestCheckFunc(
					testCertAuthBackendCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"name", name),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"allowed_names.#", "2"),
				),
			},
		},
	})
}

func TestCertAuthBackend_deprecated(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-cert-auth")
	name := acctest.RandomWithPrefix("tf-test-cert-name")

	allowedNames := []string{
		acctest.RandomWithPrefix("tf-ident-1"),
		acctest.RandomWithPrefix("tf-ident-2")}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testCertAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testCertAuthBackendConfig_deprecated(backend, name, testCertificate, allowedNames),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"name", name),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"policies.#", "2"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"ttl", "300"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"max_ttl", "600"),
					resource.TestCheckResourceAttr("vault_cert_auth_backend_role.test",
						"allowed_names.#", "2"),
				),
			},
		},
	})
}

func testCertAuthBackendDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_cert_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for Cert auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Cert auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testCertAuthBackendCheck_attrs(backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_cert_auth_backend_role.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := "auth/" + strings.Trim(backend, "/") + "/certs/" + name
		if endpoint != instanceState.ID {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, instanceState.ID)
		}

		client := testProvider.Meta().(*api.Client)
		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(backend, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "cert" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"name":                         "display_name",
			"allowed_names":                "allowed_names",
			"allowed_dns_sans":             "allowed_dns_sans",
			"allowed_email_sans":           "allowed_email_sans",
			"allowed_uri_sans":             "allowed_uri_sans",
			"allowed_organization_units":   "allowed_organization_units",
			"allowed_organizational_units": "allowed_organizational_units",
			"required_extensions":          "required_extensions",
			"token_period":                 "token_period",
			"token_policies":               "token_policies",
			"certificate":                  "certificate",
			"token_ttl":                    "token_ttl",
			"token_max_ttl":                "token_max_ttl",
			"token_bound_cidrs":            "token_bound_cidrs",
		}

		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("Expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("Expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("Expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}

			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("Expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("Expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("Expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
									break
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, endpoint)
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]

			}
			if !match {
				return fmt.Errorf("Expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}

		}

		return nil
	}
}

func testCertAuthBackendConfig_basic(backend, name, certificate string, allowedNames []string) string {
	quotedNames := make([]string, len(allowedNames))
	for idx, name := range allowedNames {
		quotedNames[idx] = fmt.Sprintf(`"%s"`, name)
	}

	return fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = "%s"
    certificate   = <<__CERTIFICATE__
%s
__CERTIFICATE__
    allowed_names  = [%s]
    backend        = "${vault_auth_backend.cert.path}"
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["test_policy_1", "test_policy_2"]
}

`, backend, name, certificate, strings.Join(quotedNames, ", "))

}

func testCertAuthBackendConfig_unset(backend, name, certificate string, allowedNames []string) string {
	quotedNames := make([]string, len(allowedNames))
	for idx, name := range allowedNames {
		quotedNames[idx] = fmt.Sprintf(`"%s"`, name)
	}

	return fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = "%s"
    certificate   = <<__CERTIFICATE__
%s
__CERTIFICATE__
    allowed_names  = [%s]
    backend        = "${vault_auth_backend.cert.path}"
}

`, backend, name, certificate, strings.Join(quotedNames, ", "))

}

func testCertAuthBackendConfig_deprecated(backend, name, certificate string, allowedNames []string) string {
	quotedNames := make([]string, len(allowedNames))
	for idx, name := range allowedNames {
		quotedNames[idx] = fmt.Sprintf(`"%s"`, name)
	}

	return fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
    path = "%s"
    type = "cert"
}

resource "vault_cert_auth_backend_role" "test" {
    name          = "%s"
    certificate   = <<__CERTIFICATE__
%s
__CERTIFICATE__
    allowed_names  = [%s]
    backend        = "${vault_auth_backend.cert.path}"
    ttl            = 300
    max_ttl        = 600
    policies       = ["test_policy_1", "test_policy_2"]
}

`, backend, name, certificate, strings.Join(quotedNames, ", "))

}
