package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceAuth(t *testing.T) {
	path := "github-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuth_initialConfig(path),
				Check:  testResourceAuth_initialCheck(path),
			},
			{
				Config: testResourceAuth_updateConfig,
				Check:  testResourceAuth_updateCheck,
			},
		},
	})
}

func testAccCheckAuthBackendDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_auth_backend" {
			continue
		}
		instanceState := rs.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		if _, ok := auths[instanceState.ID]; ok {
			return fmt.Errorf("Auth backend still exists")
		}
	}
	return nil
}

func testResourceAuth_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type        = "github"
	path        = "%s"
	description = "Test auth backend"
	tune {
		default_lease_ttl  = "3600s"
		max_lease_ttl      = "86400s"
		listing_visibility = "unauth"
	}
	local = true
}`, path)
}

func testResourceAuth_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}

		if path != expectedPath {
			return fmt.Errorf("unexpected auth path %q, expected %q", path, expectedPath)
		}

		if instanceState.Attributes["type"] != "github" {
			return fmt.Errorf("unexpected auth type")
		}

		if instanceState.Attributes["description"] != "Test auth backend" {
			return fmt.Errorf("unexpected auth description")
		}

		if v := instanceState.Attributes["tune.3452467105.default_lease_ttl"]; v != "3600s" {
			return fmt.Errorf("unexpected auth default_lease_ttl, got %s", v)
		}

		if instanceState.Attributes["tune.3452467105.max_lease_ttl"] != "86400s" {
			return fmt.Errorf("unexpected auth max_lease_ttl")
		}

		if instanceState.Attributes["tune.3452467105.listing_visibility"] != "unauth" {
			return fmt.Errorf("unexpected auth listing_visibility")
		}

		if instanceState.Attributes["local"] != "true" {
			return fmt.Errorf("unexpected auth local")
		}

		client := testProvider.Meta().(*api.Client)
		auths, err := client.Sys().ListAuth()

		if err != nil {
			return fmt.Errorf("error reading back auth: %s", err)
		}

		found := false
		for serverPath, serverAuth := range auths {
			if serverPath == expectedPath+"/" {
				found = true
				if serverAuth.Type != "github" {
					return fmt.Errorf("unexpected auth type")
				}
				if serverAuth.Description != "Test auth backend" {
					return fmt.Errorf("unexpected auth description")
				}
				if serverAuth.Config.DefaultLeaseTTL != 3600 {
					return fmt.Errorf("unexpected auth default_lease_ttl_seconds")
				}
				if serverAuth.Config.MaxLeaseTTL != 86400 {
					return fmt.Errorf("unexpected auth max_lease_ttl_seconds")
				}
				if serverAuth.Config.ListingVisibility != "unauth" {
					return fmt.Errorf("unexpected auth listing_visibility")
				}
				if serverAuth.Local != true {
					return fmt.Errorf("unexpected auth local")
				}
				break
			}
		}

		if !found {
			return fmt.Errorf("could not find auth backend %q in %+v", expectedPath, auths)
		}

		return nil
	}
}

var testResourceAuth_updateConfig = `

resource "vault_auth_backend" "test" {
	type = "ldap"
}

`

func testResourceAuth_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_auth_backend.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	name := instanceState.ID

	if name != instanceState.Attributes["type"] {
		return fmt.Errorf("id doesn't match name")
	}

	if name != "ldap" {
		return fmt.Errorf("unexpected auth name")
	}

	client := testProvider.Meta().(*api.Client)
	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading back auth: %s", err)
	}

	found := false
	for _, auth := range auths {
		if auth.Type == name {
			found = true
			if wanted := instanceState.Attributes["accessor"]; auth.Accessor != wanted {
				return fmt.Errorf("accessor is %v; wanted %v", auth.Accessor, wanted)
			}
			break
		}
	}

	if !found {
		return fmt.Errorf("could not find auth backend %s in %+v", name, auths)
	}

	return nil
}

func TestResourceAuthTune(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_auth_backend.test"
	var resAuthFirst api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuthTune_initialConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuthFirst),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.2820787064.default_lease_ttl", "60s"),
					resource.TestCheckResourceAttr(resName, "tune.2820787064.max_lease_ttl", "3600s"),
					resource.TestCheckResourceAttr(resName, "tune.2820787064.listing_visibility", "unauth"),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					checkAuthMount(backend, listingVisibility("unauth")),
					checkAuthMount(backend, defaultLeaseTtl(60)),
					checkAuthMount(backend, maxLeaseTtl(3600)),
				),
			},
			{
				Config: testResourceAuthTune_updateConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.966249371.default_lease_ttl", "60s"),
					resource.TestCheckResourceAttr(resName, "tune.966249371.max_lease_ttl", "7200s"),
					resource.TestCheckResourceAttr(resName, "tune.966249371.listing_visibility", "hidden"),
					checkAuthMount(backend, listingVisibility("hidden")),
					checkAuthMount(backend, defaultLeaseTtl(60)),
					checkAuthMount(backend, maxLeaseTtl(7200)),
				),
			},
		},
	})
}

func testResourceAuthTune_initialConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		listing_visibility = "unauth"
		max_lease_ttl      = "3600s"
		default_lease_ttl  = "60s"
	}
}`, backend)
}

func testResourceAuthTune_updateConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		max_lease_ttl      = "7200s"
		default_lease_ttl  = "60s"
	}
}`, backend)
}

func testResourceAuthTune_conflictWithTuneConfig() string {
	return `
resource "vault_auth_backend" "test" {
	type = "github"
	tune {
		max_lease_ttl      = "7200s"
		default_lease_ttl  = "60s"
	}
}`
}

func TestResourceAuthMigrateToTune(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_auth_backend.test"
	var resAuthFirst api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuthMigrateToTune_initialConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuthFirst),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					checkAuthMount(backend, defaultLeaseTtl(75)),
					checkAuthMount(backend, maxLeaseTtl(4800)),
				),
			},
			{
				Config: testResourceAuthMigrateToTune_updateConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.2271853193.max_lease_ttl", "5600s"),
					resource.TestCheckResourceAttr(resName, "tune.2271853193.default_lease_ttl", "90s"),
					checkAuthMount(backend, defaultLeaseTtl(90)),
					checkAuthMount(backend, maxLeaseTtl(5600)),
				),
			},
		},
	})
}

func testResourceAuthMigrateToTune_initialConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		max_lease_ttl     = "4800s"
		default_lease_ttl = "75s"
	}
}`, backend)
}

func testResourceAuthMigrateToTune_updateConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		max_lease_ttl      = "5600s"
		default_lease_ttl  = "90s"
	}
}`, backend)
}

func checkAuthMount(backend string, checker func(*api.AuthMount) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)
		auths, err := client.Sys().ListAuth()

		if err != nil {
			return fmt.Errorf("error reading back auth: %s", err)
		}

		found := false
		for serverPath, serverAuth := range auths {
			if serverPath == backend+"/" {
				found = true
				if serverAuth.Type != "github" {
					return fmt.Errorf("unexpected auth type")
				}

				if err := checker(serverAuth); err != nil {
					return err
				}
				break
			}
		}

		if !found {
			return fmt.Errorf("could not find auth backend %q in %+v", "github", auths)
		}

		return nil
	}
}

func listingVisibility(expected string) func(*api.AuthMount) error {
	return func(auth *api.AuthMount) error {
		actual := auth.Config.ListingVisibility
		if actual != expected {
			return fmt.Errorf("unexpected auth listing_visibility: expected %q but got %q", expected, actual)
		}
		return nil
	}
}

func defaultLeaseTtl(expected int) func(*api.AuthMount) error {
	return func(auth *api.AuthMount) error {
		actual := auth.Config.DefaultLeaseTTL
		if actual != expected {
			return fmt.Errorf("unexpected auth default_lease_ttl: expected %d but got %d", expected, actual)
		}
		return nil
	}
}

func maxLeaseTtl(expected int) func(*api.AuthMount) error {
	return func(auth *api.AuthMount) error {
		actual := auth.Config.MaxLeaseTTL
		if actual != expected {
			return fmt.Errorf("unexpected auth max_lease_ttl: expected %d but got %d", expected, actual)
		}
		return nil
	}
}
