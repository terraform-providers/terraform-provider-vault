package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func quotaRateLimitPath(name string) string {
	return "sys/quotas/rate-limit/" + name
}

func quotaRateLimitResource() *schema.Resource {
	return &schema.Resource{
		Create: quotaRateLimitCreate,
		Read:   quotaRateLimitRead,
		Update: quotaRateLimitUpdate,
		Delete: quotaRateLimitDelete,
		Exists: quotaRateLimitExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the quota.",
				ForceNew:    true,
			},
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Path of the mount or namespace to apply the quota. A blank path configures a global rate limit quota.",
			},
			"rate": {
				Type:         schema.TypeFloat,
				Required:     true,
				Description:  "The maximum number of requests at any given second to be allowed by the quota rule. The rate must be positive.",
				ValidateFunc: validation.FloatAtLeast(0.0),
			},
			"interval": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The duration to enforce rate limiting for (default \"1s\").",
				StateFunc:    durationSecond,
				ValidateFunc: validateDurationSecond,
				Default:      "1s",
			},
			"block_interval": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "If set, when a client reaches a rate limit threshold, the client will be prohibited from any further requests until after the 'block_interval' has elapsed.",
				StateFunc:    durationSecond,
				ValidateFunc: validateDurationSecond,
			},
		},
	}
}

func quotaRateLimitCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	path := quotaRateLimitPath(name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating Resource Rate Limit Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get("path").(string)
	data["rate"] = d.Get("rate").(float64)

	if intervalRaw, ok := d.GetOk("interval"); ok {
		data["interval"] = intervalRaw.(string)
	}

	if blockIntervalRaw, ok := d.GetOk("block_interval"); ok {
		data["block_interval"] = blockIntervalRaw.(string)
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error creating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Created Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(d, meta)
}

func quotaRateLimitRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Reading Resource Rate Limit Quota %s", name)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Resource Rate Limit Quota %s: %s", name, err)
	}

	if resp == nil {
		log.Printf("[WARN] Resource Rate Limit Quota %s not found, removing from state", name)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"path", "rate", "interval", "block_interval"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting %s for Resource Rate Limit Quota %s: %q", k, name, err)
			}
		}
	}

	return nil
}

func quotaRateLimitUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Updating Resource Rate Limit Quota %s", name)

	data := map[string]interface{}{}
	data["path"] = d.Get("path").(string)
	data["rate"] = d.Get("rate").(float64)

	if intervalRaw, ok := d.GetOk("interval"); ok {
		data["interval"] = intervalRaw.(string)
	}

	if blockIntervalRaw, ok := d.GetOk("block_interval"); ok {
		data["block_interval"] = blockIntervalRaw.(string)
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error updating Resource Rate Limit Quota %s: %s", name, err)
	}
	log.Printf("[DEBUG] Updated Resource Rate Limit Quota %s", name)

	return quotaRateLimitRead(d, meta)
}

func quotaRateLimitDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Deleting Resource Rate Limit Quota %s", name)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting Resource Rate Limit Quota %s", name)
	}
	log.Printf("[DEBUG] Deleted Resource Rate Limit Quota %s", name)

	return nil
}

func quotaRateLimitExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	name := d.Id()
	path := quotaRateLimitPath(name)

	log.Printf("[DEBUG] Checking if Resource Rate Limit Quota %s exists", name)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Resource Rate Limit Quota %s exists: %s", name, err)
	}

	log.Printf("[DEBUG] Checked if Resource Rate Limit Quota %s exists", name)
	return secret != nil, nil
}

func validateDurationSecond(i interface{}, k string) (s []string, es []error) {
	if _, err := util.ParseDurationSecond(i); err != nil {
		es = append(es, fmt.Errorf("expected '%s' to be a valid duration second", k))
	}
	return
}

func durationSecond(i interface{}) string {
	d, _ := util.ParseDurationSecond(i)
	return fmt.Sprint(d.Truncate(time.Second).Seconds())
}
