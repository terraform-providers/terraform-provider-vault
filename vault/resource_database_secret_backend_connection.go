package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

var (
	databaseSecretBackendConnectionBackendFromPathRegex = regexp.MustCompile("^(.+)/config/.+$")
	databaseSecretBackendConnectionNameFromPathRegex    = regexp.MustCompile("^.+/config/(.+$)")
	dbBackendTypes                                      = []string{"cassandra", "hana", "mongodb", "mssql", "mysql", "mysql_rds", "mysql_aurora", "mysql_legacy", "postgresql", "oracle", "elasticsearch"}
)

func databaseSecretBackendConnectionResource() *schema.Resource {
	return &schema.Resource{
		Create: databaseSecretBackendConnectionCreate,
		Read:   databaseSecretBackendConnectionRead,
		Update: databaseSecretBackendConnectionUpdate,
		Delete: databaseSecretBackendConnectionDelete,
		Exists: databaseSecretBackendConnectionExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the database connection.",
				ForceNew:    true,
			},
			"verify_connection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Specifies if the connection is verified during initial configuration.",
				Default:     true,
			},
			"allowed_roles": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of roles that are allowed to use this connection.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"root_rotation_statements": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of database statements to be executed to rotate the root user's credentials.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"data": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "A map of sensitive data to pass to the endpoint. Useful for templated connection strings.",
				Sensitive:   true,
			},

			"elasticsearch": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Connection parameters for the elasticsearch-database-plugin.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"url": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The URL for Elasticsearch's API",
						},
						"username": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The username to be used in the connection URL",
						},
						"password": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The password to be used in the connection URL",
							Sensitive:   true,
						},
					},
				},
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("elasticsearch", dbBackendTypes),
			},

			"cassandra": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Connection parameters for the cassandra-database-plugin plugin.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"hosts": {
							Type: schema.TypeList,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional:    true,
							Description: "Cassandra hosts to connect to.",
						},
						"port": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "The transport port to use to connect to Cassandra.",
							Default:     9042,
						},
						"username": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The username to use when authenticating with Cassandra.",
						},
						"password": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The password to use when authenticating with Cassandra.",
							Sensitive:   true,
						},
						"tls": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Whether to use TLS when connecting to Cassandra.",
							Default:     true,
						},
						"insecure_tls": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Whether to skip verification of the server certificate when using TLS.",
							Default:     false,
						},
						"pem_bundle": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
							Sensitive:   true,
						},
						"pem_json": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Specifies JSON containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.",
							Sensitive:   true,
						},
						"protocol_version": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     2,
							Description: "The CQL protocol version to use.",
						},
						"connect_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Default:     5,
							Description: "The number of seconds to use as a connection timeout.",
						},
					},
				},
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("cassandra", dbBackendTypes),
			},

			"mongodb": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mongodb-database-plugin plugin.",
				Elem:          mongoDbConnectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mongodb", dbBackendTypes),
			},

			"mongodbatlas": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Connection parameters for the mongodbatlas-database-plugin plugin.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"private_key": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Private Programmatic API Key used to connect with MongoDB Atlas API.",
							Sensitive:   true,
						},
						"public_key": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Public Programmatic API Key used to authenticate with the MongoDB Atlas API.",
						},
						"project_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Project ID the Database User should be created within.",
						},
					},
				},
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mongodbatlas", dbBackendTypes),
			},

			"hana": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the hana-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("hana", dbBackendTypes),
			},

			"mssql": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mssql-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mssql", dbBackendTypes),
			},

			"mysql": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mysql", dbBackendTypes),
			},
			"mysql_rds": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-rds-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mysql_rds", dbBackendTypes),
			},
			"mysql_aurora": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-aurora-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mysql_aurora", dbBackendTypes),
			},
			"mysql_legacy": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the mysql-legacy-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("mysql_legacy", dbBackendTypes),
			},

			"postgresql": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the postgresql-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("postgresql", dbBackendTypes),
			},

			"oracle": {
				Type:          schema.TypeList,
				Optional:      true,
				Description:   "Connection parameters for the oracle-database-plugin plugin.",
				Elem:          connectionStringResource(),
				MaxItems:      1,
				ConflictsWith: util.CalculateConflictsWith("oracle", dbBackendTypes),
			},

			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Vault mount to configure.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
		},
	}
}

func connectionStringResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"connection_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Connection string to use to connect to the database.",
			},
			"max_open_connections": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of open connections to the database.",
				Default:     2,
			},
			"max_idle_connections": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of idle connections to the database.",
			},
			"max_connection_lifetime": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum number of seconds a connection may be reused.",
			},
		},
	}
}

func mongoDbConnectionStringResource() *schema.Resource {
	r := connectionStringResource()
	r.Schema["tls_ca"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Description: "x509 CA file for validating the certificate presented by the MongoDB server. Must be PEM encoded.",
	}
	return r
}

func getDatabasePluginName(d *schema.ResourceData) (string, error) {
	switch {
	case len(d.Get("cassandra").([]interface{})) > 0:
		return "cassandra-database-plugin", nil
	case len(d.Get("hana").([]interface{})) > 0:
		return "hana-database-plugin", nil
	case len(d.Get("mongodbatlas").([]interface{})) > 0:
		return "mongodbatlas-database-plugin", nil
	case len(d.Get("mongodb").([]interface{})) > 0:
		return "mongodb-database-plugin", nil
	case len(d.Get("mssql").([]interface{})) > 0:
		return "mssql-database-plugin", nil
	case len(d.Get("mysql").([]interface{})) > 0:
		return "mysql-database-plugin", nil
	case len(d.Get("mysql_rds").([]interface{})) > 0:
		return "mysql-rds-database-plugin", nil
	case len(d.Get("mysql_aurora").([]interface{})) > 0:
		return "mysql-aurora-database-plugin", nil
	case len(d.Get("mysql_legacy").([]interface{})) > 0:
		return "mysql-legacy-database-plugin", nil
	case len(d.Get("oracle").([]interface{})) > 0:
		return "oracle-database-plugin", nil
	case len(d.Get("postgresql").([]interface{})) > 0:
		return "postgresql-database-plugin", nil
	case len(d.Get("elasticsearch").([]interface{})) > 0:
		return "elasticsearch-database-plugin", nil
	default:
		return "", fmt.Errorf("at least one database plugin must be configured")
	}
}

func getDatabaseAPIData(d *schema.ResourceData) (map[string]interface{}, error) {
	plugin, err := getDatabasePluginName(d)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"plugin_name": plugin,
	}

	switch plugin {
	case "cassandra-database-plugin":
		if v, ok := d.GetOk("cassandra.0.hosts"); ok {
			log.Printf("[DEBUG] Cassandra hosts: %v", v.([]interface{}))
			var hosts []string
			for _, host := range v.([]interface{}) {
				if v == nil {
					continue
				}
				hosts = append(hosts, host.(string))
			}
			data["hosts"] = strings.Join(hosts, ",")
		}
		if v, ok := d.GetOkExists("cassandra.0.port"); ok {
			data["port"] = v.(int)
		}
		if v, ok := d.GetOk("cassandra.0.username"); ok {
			data["username"] = v.(string)
		}
		if v, ok := d.GetOk("cassandra.0.password"); ok {
			data["password"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.tls"); ok {
			data["tls"] = v.(bool)
		}
		if v, ok := d.GetOkExists("cassandra.0.insecure_tls"); ok {
			data["insecure_tls"] = v.(bool)
		}
		if v, ok := d.GetOkExists("cassandra.0.pem_bundle"); ok {
			data["pem_bundle"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.pem_json"); ok {
			data["pem_json"] = v.(string)
		}
		if v, ok := d.GetOkExists("cassandra.0.protocol_version"); ok {
			data["protocol_version"] = v.(int)
		}
		if v, ok := d.GetOkExists("cassandra.0.connect_timeout"); ok {
			data["connect_timeout"] = v.(int)
		}
	case "hana-database-plugin":
		setDatabaseConnectionData(d, "hana.0.", data)
	case "mongodb-database-plugin":
		setMongoDbDatabaseConnectionData(d, "mongodb.0.", data)
	case "mongodbatlas-database-plugin":
		if v, ok := d.GetOk("mongodbatlas.0.public_key"); ok {
			data["public_key"] = v.(string)
		}
		if v, ok := d.GetOk("mongodbatlas.0.private_key"); ok {
			data["private_key"] = v.(string)
		}
		if v, ok := d.GetOk("mongodbatlas.0.project_id"); ok {
			data["project_id"] = v.(string)
		}
	case "mssql-database-plugin":
		setDatabaseConnectionData(d, "mssql.0.", data)
	case "mysql-database-plugin":
		setDatabaseConnectionData(d, "mysql.0.", data)
	case "mysql-rds-database-plugin":
		setDatabaseConnectionData(d, "mysql_rds.0.", data)
	case "mysql-aurora-database-plugin":
		setDatabaseConnectionData(d, "mysql_aurora.0.", data)
	case "mysql-legacy-database-plugin":
		setDatabaseConnectionData(d, "mysql_legacy.0.", data)
	case "oracle-database-plugin":
		setDatabaseConnectionData(d, "oracle.0.", data)
	case "postgresql-database-plugin":
		setDatabaseConnectionData(d, "postgresql.0.", data)
	case "elasticsearch-database-plugin":
		setElasticsearchDatabaseConnectionData(d, "elasticsearch.0.", data)
	}

	return data, nil
}

func getConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}
	if v, ok := d.GetOk(prefix + "connection_url"); ok {
		result["connection_url"] = v.(string)
	} else {
		if v, ok := data["connection_url"]; ok {
			result["connection_url"] = v.(string)
		}
	}
	if v, ok := data["max_open_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_open_connections"] = n
		}
	}
	if v, ok := data["max_idle_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_idle_connections"] = n
		}
	}
	if v, ok := data["max_connection_lifetime"]; ok {
		n, err := time.ParseDuration(v.(string))
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_connection_lifetime"] = n.Seconds()
		}
	}
	return []map[string]interface{}{result}
}

func getMongoDbConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}
	if v, ok := d.GetOk(prefix + "connection_url"); ok {
		result["connection_url"] = v.(string)
	} else {
		if v, ok := data["connection_url"]; ok {
			result["connection_url"] = v.(string)
		}
	}
	if v, ok := data["max_open_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_open_connections"] = n
		}
	}
	if v, ok := data["max_idle_connections"]; ok {
		n, err := v.(json.Number).Int64()
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_idle_connections"] = n
		}
	}
	if v, ok := data["max_connection_lifetime"]; ok {
		n, err := time.ParseDuration(v.(string))
		if err != nil {
			log.Printf("[WARN] Non-number %s returned from Vault server: %s", v, err)
		} else {
			result["max_connection_lifetime"] = n.Seconds()
		}
	}
	if v, ok := d.GetOk(prefix + "tls_ca"); ok {
		result["tls_ca"] = v.(string)
	} else {
		if v, ok := data["tls_ca"]; ok {
			result["tls_ca"] = v.(string)
		}
	}
	return []map[string]interface{}{result}
}

func getElasticsearchConnectionDetailsFromResponse(d *schema.ResourceData, prefix string, resp *api.Secret) []map[string]interface{} {
	details := resp.Data["connection_details"]
	data, ok := details.(map[string]interface{})
	if !ok {
		return nil
	}
	result := map[string]interface{}{}
	if v, ok := d.GetOk(prefix + "url"); ok {
		result["url"] = v.(string)
	} else {
		if v, ok := data["url"]; ok {
			result["url"] = v.(string)
		}
	}

	if v, ok := data["username"]; ok {
		result["username"] = v.(string)
	}
	if v, ok := data["password"]; ok {
		result["password"] = v.(string)
	} else if v, ok := d.GetOk(prefix + "password"); ok {
		// keep the password we have in state/config if the API doesn't return one
		result["password"] = v.(string)
	}

	return []map[string]interface{}{result}
}

func setDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "connection_url"); ok {
		data["connection_url"] = v.(string)
	}
	if v, ok := d.GetOk(prefix + "max_open_connections"); ok {
		data["max_open_connections"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "max_idle_connections"); ok {
		data["max_idle_connections"] = v.(int)
	}
	if v, ok := d.GetOkExists(prefix + "max_connection_lifetime"); ok {
		data["max_connection_lifetime"] = fmt.Sprintf("%ds", v)
	}
}

func setMongoDbDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	setDatabaseConnectionData(d, prefix, data)
	if v, ok := d.GetOkExists(prefix + "tls_ca"); ok {
		data["tls_ca"] = v.(string)
	}
}

func setElasticsearchDatabaseConnectionData(d *schema.ResourceData, prefix string, data map[string]interface{}) {
	if v, ok := d.GetOk(prefix + "url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "username"); ok {
		data["username"] = v.(string)
	}

	if v, ok := d.GetOk(prefix + "password"); ok {
		data["password"] = v.(string)
	}
}

func databaseSecretBackendConnectionCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendConnectionPath(backend, name)

	data, err := getDatabaseAPIData(d)
	if err != nil {
		return err
	}

	if v, ok := d.GetOkExists("verify_connection"); ok {
		data["verify_connection"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allowed_roles"); ok {
		var roles []string
		for _, role := range v.([]interface{}) {
			roles = append(roles, role.(string))
		}
		data["allowed_roles"] = strings.Join(roles, ",")
	}

	if v, ok := d.GetOkExists("root_rotation_statements"); ok {
		data["root_rotation_statements"] = v
	}

	if m, ok := d.GetOkExists("data"); ok {
		for k, v := range m.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	log.Printf("[DEBUG] Writing connection config to %q", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error configuring database connection %q: %s", path, err)
	}

	d.SetId(path)
	log.Printf("[DEBUG] Wrote database connection config %q", path)

	return databaseSecretBackendConnectionRead(d, meta)
}

func databaseSecretBackendConnectionRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	backend, err := databaseSecretBackendConnectionBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for database connection: %s", path, err)
	}

	name, err := databaseSecretBackendConnectionNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for database connection: %s", path, err)
	}

	log.Printf("[DEBUG] Reading database connection config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read database connection config %q", path)
	if resp == nil {
		log.Printf("[WARN] Database connection %q not found, removing it from state", path)
		d.SetId("")
		return nil
	}

	switch resp.Data["plugin_name"].(string) {
	case "cassandra-database-plugin":
		details := resp.Data["connection_details"]
		data, ok := details.(map[string]interface{})
		if ok {
			result := map[string]interface{}{}

			if v, ok := data["hosts"]; ok {
				result["hosts"] = strings.Split(v.(string), ",")
			}
			if v, ok := data["port"]; ok {
				port, err := v.(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("unexpected non-number %q returned as port from Vault: %s", v, err)
				}
				result["port"] = port
			}
			if v, ok := data["username"]; ok {
				result["username"] = v.(string)
			}
			if v, ok := data["password"]; ok {
				result["password"] = v.(string)
			} else if v, ok := d.GetOk("cassandra.0.password"); ok {
				// keep the password we have in state/config if the API doesn't return one
				result["password"] = v.(string)
			}
			if v, ok := data["tls"]; ok {
				result["tls"] = v.(bool)
			}
			if v, ok := data["insecure_tls"]; ok {
				result["insecure_tls"] = v.(bool)
			}
			if v, ok := data["pem_bundle"]; ok {
				result["pem_bundle"] = v.(string)
			} else if v, ok := d.GetOk("cassandra.0.pem_bundle"); ok {
				result["pem_bundle"] = v.(string)
			}
			if v, ok := data["pem_json"]; ok {
				result["pem_json"] = v.(string)
			} else if v, ok := d.GetOk("cassandra.0.pem_json"); ok {
				result["pem_json"] = v.(string)
			}
			if v, ok := data["protocol_version"]; ok {
				protocol, err := v.(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("unexpected non-number %q returned as protocol_version from Vault: %s", v, err)
				}
				result["protocol_version"] = int64(protocol)
			}
			if v, ok := data["connect_timeout"]; ok {
				timeout, err := v.(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("unexpected non-number %q returned as connect_timeout from Vault: %s", v, err)
				}
				result["connect_timeout"] = timeout
			}
			d.Set("cassandra", []map[string]interface{}{result})
		}
	case "hana-database-plugin":
		d.Set("hana", getConnectionDetailsFromResponse(d, "hana.0.", resp))
	case "mongodb-database-plugin":
		d.Set("mongodb", getMongoDbConnectionDetailsFromResponse(d, "mongodb.0.", resp))
	case "mongodbatlas-database-plugin":
		details := resp.Data["connection_details"]
		data, ok := details.(map[string]interface{})
		if ok {
			result := map[string]interface{}{}

			if v, ok := data["public_key"]; ok {
				result["public_key"] = v.(string)
			}
			if v, ok := data["private_key"]; ok {
				result["private_key"] = v.(string)
			}
			if v, ok := data["project_id"]; ok {
				result["project_id"] = v.(string)
			}
			d.Set("mongodbatlas", []map[string]interface{}{result})
		}
	case "mssql-database-plugin":
		d.Set("mssql", getConnectionDetailsFromResponse(d, "mssql.0.", resp))
	case "mysql-database-plugin":
		d.Set("mysql", getConnectionDetailsFromResponse(d, "mysql.0.", resp))
	case "mysql-rds-database-plugin":
		d.Set("mysql_rds", getConnectionDetailsFromResponse(d, "mysql_rds.0.", resp))
	case "mysql-aurora-database-plugin":
		d.Set("mysql_aurora", getConnectionDetailsFromResponse(d, "mysql_aurora.0.", resp))
	case "mysql-legacy-database-plugin":
		d.Set("mysql_legacy", getConnectionDetailsFromResponse(d, "mysql_legacy.0.", resp))
	case "oracle-database-plugin":
		d.Set("oracle", getConnectionDetailsFromResponse(d, "oracle.0.", resp))
	case "postgresql-database-plugin":
		d.Set("postgresql", getConnectionDetailsFromResponse(d, "postgresql.0.", resp))
	case "elasticsearch-database-plugin":
		d.Set("elasticsearch", getElasticsearchConnectionDetailsFromResponse(d, "elasticsearch.0.", resp))
	}

	if err != nil {
		return fmt.Errorf("error reading response for %q: %s", path, err)
	}

	var roles []string
	for _, role := range resp.Data["allowed_roles"].([]interface{}) {
		roles = append(roles, role.(string))
	}

	d.Set("allowed_roles", roles)
	d.Set("backend", backend)
	d.Set("name", name)
	d.Set("root_rotation_statements", resp.Data["root_credentials_rotate_statements"])
	if v, ok := resp.Data["verify_connection"]; ok {
		d.Set("verify_connection", v.(bool))
	}

	return nil
}

func databaseSecretBackendConnectionUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := databaseSecretBackendConnectionPath(backend, name)

	data, err := getDatabaseAPIData(d)
	if err != nil {
		return err
	}

	if v, ok := d.GetOkExists("verify_connection"); ok {
		data["verify_connection"] = v.(bool)
	}

	if v, ok := d.GetOkExists("allowed_roles"); ok {
		var roles []string
		for _, role := range v.([]interface{}) {
			roles = append(roles, role.(string))
		}
		data["allowed_roles"] = strings.Join(roles, ",")
	}

	if v, ok := d.GetOkExists("root_rotation_statements"); ok {
		data["root_rotation_statements"] = v
	}

	if m, ok := d.GetOkExists("data"); ok {
		for k, v := range m.(map[string]interface{}) {
			// Vault does not return the password in the API. If the root credentials have been rotated, sending
			// the old password in the update request would break the connection config. Thus we only send it,
			// if it actually changed, to still support updating it for non-rotated cases.
			if k == "password" && d.HasChange(k) {
				data[k] = v.(string)
			}
		}
	}

	log.Printf("[DEBUG] Writing connection config to %q", path)
	_, err = client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error configuring database connection %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote database connection config %q", path)

	return databaseSecretBackendConnectionRead(d, meta)
}

func databaseSecretBackendConnectionDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Removing database connection config %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error removing database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed database connection config %q", path)

	return nil
}

func databaseSecretBackendConnectionExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if database connection config %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if database connection config %q exists", path)
	return resp != nil, nil
}

func databaseSecretBackendConnectionPath(backend, name string) string {
	return strings.Trim(backend, "/") + "/config/" + strings.Trim(name, "/")
}

func databaseSecretBackendConnectionNameFromPath(path string) (string, error) {
	if !databaseSecretBackendConnectionNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := databaseSecretBackendConnectionNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func databaseSecretBackendConnectionBackendFromPath(path string) (string, error) {
	if !databaseSecretBackendConnectionBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := databaseSecretBackendConnectionBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
