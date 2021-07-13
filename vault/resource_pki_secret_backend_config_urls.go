package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func pkiSecretBackendConfigUrlsResource() *schema.Resource {
	return &schema.Resource{
		Create: pkiSecretBackendConfigUrlsCreate,
		Read:   pkiSecretBackendConfigUrlsRead,
		Update: pkiSecretBackendConfigUrlsUpdate,
		Delete: pkiSecretBackendConfigUrlsDelete,
		Exists: pkiSecretBackendConfigUrlsExists,

		Importer: &schema.ResourceImporter{
			State: resourcePkiSecretBackendConfigUrlsImport,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path of the PKI secret backend the resource belongs to.",
			},
			"issuing_certificates": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the Issuing Certificate field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"crl_distribution_points": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the CRL Distribution Points field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ocsp_servers": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies the URL values for the OCSP Servers field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func pkiSecretBackendConfigUrlsCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigUrlsPath(backend)

	issuingCertificates := d.Get("issuing_certificates")
	crlDistributionsPoints := d.Get("crl_distribution_points")
	ocspServers := d.Get("ocsp_servers")

	data := map[string]interface{}{
		"issuing_certificates":    issuingCertificates,
		"crl_distribution_points": crlDistributionsPoints,
		"ocsp_servers":            ocspServers,
	}

	log.Printf("[DEBUG] Creating URL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error creating URL config PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Created URL config on PKI secret backend %q", backend)

	d.SetId(fmt.Sprintf("%s/config/urls", backend))
	return pkiSecretBackendConfigUrlsRead(d, meta)
}

func pkiSecretBackendConfigUrlsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	backend := pkiSecretBackendConfigUrlsPath(path)

	log.Printf("[DEBUG] Reading URL config from PKI secret backend %q", backend)
	config, err := client.Logical().Read(path)

	if err != nil {
		return fmt.Errorf("error reading URL config on PKI secret backend %q: %s", path, err)
	}

	if config == nil {
		log.Printf("[WARN] Removing URL config path %q as its ID is invalid", path)
		d.SetId("")
		return nil
	}

	d.Set("issuing_certificates", config.Data["issuing_certificates"])
	d.Set("crl_distribution_points", config.Data["crl_distribution_points"])
	d.Set("ocsp_servers", config.Data["ocsp_servers"])

	return nil
}

func pkiSecretBackendConfigUrlsUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)

	path := pkiSecretBackendConfigUrlsPath(backend)

	issuingCertificates := d.Get("issuing_certificates")
	crlDistributionsPoints := d.Get("crl_distribution_points")
	ocspServers := d.Get("ocsp_servers")

	data := map[string]interface{}{
		"issuing_certificates":    issuingCertificates,
		"crl_distribution_points": crlDistributionsPoints,
		"ocsp_servers":            ocspServers,
	}

	log.Printf("[DEBUG] Updating URL config on PKI secret backend %q", backend)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating URL config for PKI secret backend %q: %s", backend, err)
	}
	log.Printf("[DEBUG] Updated URL config on PKI secret backend %q", backend)

	return pkiSecretBackendConfigUrlsRead(d, meta)

}

func pkiSecretBackendConfigUrlsDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func pkiSecretBackendConfigUrlsExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if config urls %q exists", path)
	config_urls, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if config urls %q exists: %s", path, err)
	}
	if config_urls == nil {
		return true, fmt.Errorf("config urls %q could not be found", path)
	}

	log.Printf("[DEBUG] Checked if config urls %q exists", path)
	return config_urls != nil, nil
}

func resourcePkiSecretBackendConfigUrlsImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	// The import command takes only the backend name, since the actual path is always suffixed with /config/urls
	pki_secret_backend_name := d.Id()
	config_urls_path := pkiSecretBackendConfigUrlsPath(pki_secret_backend_name)

	// Update the backend and the id attributes accordingly
	d.Set("backend", pki_secret_backend_name)
	d.SetId(config_urls_path)

	return []*schema.ResourceData{d}, nil
}

func pkiSecretBackendConfigUrlsPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/urls"
}
