# Ansible Role: Headscale
![CI](https://github.com/hampusstrom/ansible-role-headscale/actions/workflows/ci.yml/badge.svg)

An ansible role to install and configure Headscale, An open source, self-hosted implementation of the Tailscale control server.

It's awesome, check it out: [juanfont/Headscale](https://github.com/juanfont/headscale)

## Disclaimer
The author of this project is in no way affiliated with the headscale project or Tailscale Inc.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**USE AT YOUR OWN RISK**

## Compatibility
This role has been tested on the following platforms:

* CentOS 8 x64
* Debian 10 x64
* Debian 11 x64
* Ubuntu Server 20.04 x64
* Ubuntu Server 22.04 x64

## Installation
### ansible-galaxy
```
ansible-galaxy install hampusstrom.headscale
```

### Manual Installation
Current user only:
```
git clone https://github.com/hampusstrom/ansible-role-headscale.git ~/.ansible/roles/hampusstrom.headscale
```
System wide:
```
git clone https://github.com/hampusstrom/ansible-role-headscale.git /etc/ansible/roles/hampusstrom.headscale
```

## Requirements
This role has no out-of-the-ordinary requirements and should work anywhere that ansible, headscale and systemd runs.

### GitHub API
This role makes use of the GitHub API.

The GitHub API is rate-limited.

Unauthenticated users are only allowed to make 60 request per hour.

If you are a developer, you may be hitting this limit easily.

To work around this you can retrieve a Personal Access Token from: https://github.com/settings/tokens/new

Fill in the access token details in the headscale_github_api_* variables.

`headscale_github_api_username: your_github_login_username`

`headscale_github_api_password: your_personal_access_token`

`headscale_github_api_auth: true`

### Init system(s): **systemd**
### Root required: **yes**
Since we require root, use this role in a playbook that has `become:yes` globally defined or call this role using the `become: yes` keyword.
```yaml
- hosts: headscale
  become: yes
  roles:
    - role: hampusstrom.headscale

# OR

- hosts: headscale
  roles:
    - role: hampusstrom.headscale
      become: yes
```

## Role Variables
A complete description of all available variables can be found under `defaults/main.yaml`.

### Variable Naming Convention
Variables related to this role are always prefixed by `headscale_`.

#### **headscale_version**

Defines the version of headscale to download and install on the target machines.
Can be either a version number (without 'v' prefix). I.e. **0.16.4** or **latest**

Latest will automatically retrieve the latest release tag from the [juanfont/headscale](https://github.com/juanfont/headscale) Github repository.

default: `latest`

#### **headscale_config**
The contents of the headscale config.yaml file expressed as a yaml object.
Check the default config in the headscale project for inspiration.
As of writing the following minimum values are required for version 0.20.0 of headscale.
```yaml
headscale_config:
  server_url: "http://127.0.01:8080"
  listen_addr: 127.0.0.1:8080
  private_key_path: "{{ headscale_lib_dir_path }}/private.key"
  db_type: sqlite3
  unix_socket: "{{ headscale_run_dir_path }}/headscale.sock"
  ip_prefixes:
    - 100.64.0.0/10
  noise:
    private_key_path: "{{ headscale_lib_dir_path }}/noise_private.key"
```

### **headscale_acl**
The contents of the headscale acl.yaml file expressed as a yaml object.
#### **headscale_github_repository**
Defines the user/repo to use when looking for and downloading the headscale binary.
Can be changed to another repo to allow installations of forks for example.

default: `juanfont/headscale`

#### **headscale_remove_unmanaged_users**
If set to true any users not specified in headscale_users will be permanently deleted.

**Use at your own risk**

default: `false`

#### **headscale_users**
A list of users that should be created, and not removed if used together with headscale_remove_unmanaged_users.

default: `[]`

#### **headscale_binary_path**

Defines where the headscale binary will be downloaded and installed to.

default: `/usr/local/bin/headscale`

#### **headscale_user_name**
Defines the name of the system user that should run the headscale systemd daemon.
Will be created if it not already exists.

default: `headscale`

#### **headscale_user_group**
Defines the name of the primary group for the headscale_user_name user.

default: `{{ headscale_user_name }}`

#### **headscale_user_uid**
Defines the user ID of the `headscale_user_name` user.

default: `777`

#### **headscale_user_gid**
Defines the group ID of the `headscale_user_group` group.

default: `{{ headscale_user_uid }}`

#### **headscale_etc_dir_path**

Defines the path in which headscale's configuration data should recide.
You should normally not have to change this, but for some custom configurations/forks the option is there.

default: `/etc/headscale`

#### **headscale_lib_dir_path**

Defines the path in which headscale's library data should recide.
You should normally not have to change this, but for some custom configurations/forks the option is there.

default: `/var/lib/headscale`

#### **headscale_run_dir_path**

Defines the path in which headscale's UNIX socket should recide.
You should normally not have to change this, but for some custom configurations/forks the option is there.
The unix_socket configuration entry should point to a .sock file in this directory.
i.e. unix_socket: /var/run/headscale/headscale.sock

default: `/var/run/headscale`

#### **headscale_db_path**
Path for the sqlite database file.

default: `{{ headscale_lib_dir_path }}/db.sqlite`

#### **headscale_backup_dir_path**
Path for where database backups will be stored.
Backups are automatically created before any upgrade of headscale.
If you choose to downgrade headscale, it is highly recommended to also restore your database.
To do this, simply stop headscale, copy the db file to headscale_db_path and restart headscale.

default: `{{ headscale_lib_dir_path }}/backups`

## Example Playbook
Do note that you should always check the official headscale documentation to make sure that you have any and all required values populated for your version of headscale.
I highly recommend copying [The official config example](https://github.com/juanfont/headscale/blob/main/config-example.yaml) and using it as a base for your configuration.
```yaml
---
---
# Run with command:
# ansible-playbook- i "yourinventoryfile" -K example-playbook.yml
- hosts: all
  become: yes
  vars:
    headscale_version: 0.20.0
    headscale_config:
    # headscale will look for a configuration file named `config.yaml` (or `config.json`) in the following order:
    #
    # - `/etc/headscale`
    # - `~/.headscale`
    # - current working directory

    # The url clients will connect to.
    # Typically this will be a domain like:
    #
    # https://myheadscale.example.com:443
    #
    server_url: http://127.0.0.1:8080

    # Address to listen to / bind to on the server
    #
    # For production:
    # listen_addr: 0.0.0.0:8080
    listen_addr: 127.0.0.1:8080

    # Address to listen to /metrics, you may want
    # to keep this endpoint private to your internal
    # network
    #
    metrics_listen_addr: 127.0.0.1:9090

    # Address to listen for gRPC.
    # gRPC is used for controlling a headscale server
    # remotely with the CLI
    # Note: Remote access _only_ works if you have
    # valid certificates.
    #
    # For production:
    # grpc_listen_addr: 0.0.0.0:50443
    grpc_listen_addr: 127.0.0.1:50443

    # Allow the gRPC admin interface to run in INSECURE
    # mode. This is not recommended as the traffic will
    # be unencrypted. Only enable if you know what you
    # are doing.
    grpc_allow_insecure: false

    # Private key used to encrypt the traffic between headscale
    # and Tailscale clients.
    # The private key file will be autogenerated if it's missing.
    #
    # For production:
    # /var/lib/headscale/private.key
    private_key_path: ./private.key

    # The Noise section includes specific configuration for the
    # TS2021 Noise protocol
    noise:
      # The Noise private key is used to encrypt the
      # traffic between headscale and Tailscale clients when
      # using the new Noise-based protocol. It must be different
      # from the legacy private key.
      #
      # For production:
      # private_key_path: /var/lib/headscale/noise_private.key
      private_key_path: ./noise_private.key

    # List of IP prefixes to allocate tailaddresses from.
    # Each prefix consists of either an IPv4 or IPv6 address,
    # and the associated prefix length, delimited by a slash.
    # While this looks like it can take arbitrary values, it
    # needs to be within IP ranges supported by the Tailscale
    # client.
    # IPv6: https://github.com/tailscale/tailscale/blob/22ebb25e833264f58d7c3f534a8b166894a89536/net/tsaddr/tsaddr.go#LL81C52-L81C71
    # IPv4: https://github.com/tailscale/tailscale/blob/22ebb25e833264f58d7c3f534a8b166894a89536/net/tsaddr/tsaddr.go#L33
    ip_prefixes:
      - fd7a:115c:a1e0::/48
      - 100.64.0.0/10

    # DERP is a relay system that Tailscale uses when a direct
    # connection cannot be established.
    # https://tailscale.com/blog/how-tailscale-works/#encrypted-tcp-relays-derp
    #
    # headscale needs a list of DERP servers that can be presented
    # to the clients.
    derp:
      server:
        # If enabled, runs the embedded DERP server and merges it into the rest of the DERP config
        # The Headscale server_url defined above MUST be using https, DERP requires TLS to be in place
        enabled: false

        # Region ID to use for the embedded DERP server.
        # The local DERP prevails if the region ID collides with other region ID coming from
        # the regular DERP config.
        region_id: 999

        # Region code and name are displayed in the Tailscale UI to identify a DERP region
        region_code: "headscale"
        region_name: "Headscale Embedded DERP"

        # Listens over UDP at the configured address for STUN connections - to help with NAT traversal.
        # When the embedded DERP server is enabled stun_listen_addr MUST be defined.
        #
        # For more details on how this works, check this great article: https://tailscale.com/blog/how-tailscale-works/
        stun_listen_addr: "0.0.0.0:3478"

      # List of externally available DERP maps encoded in JSON
      urls:
        - https://controlplane.tailscale.com/derpmap/default

      # Locally available DERP map files encoded in YAML
      #
      # This option is mostly interesting for people hosting
      # their own DERP servers:
      # https://tailscale.com/kb/1118/custom-derp-servers/
      #
      # paths:
      #   - /etc/headscale/derp-example.yaml
      paths: []

      # If enabled, a worker will be set up to periodically
      # refresh the given sources and update the derpmap
      # will be set up.
      auto_update_enabled: true

      # How often should we check for DERP updates?
      update_frequency: 24h

    # Disables the automatic check for headscale updates on startup
    disable_check_updates: false

    # Time before an inactive ephemeral node is deleted?
    ephemeral_node_inactivity_timeout: 30m

    # Period to check for node updates within the tailnet. A value too low will severely affect
    # CPU consumption of Headscale. A value too high (over 60s) will cause problems
    # for the nodes, as they won't get updates or keep alive messages frequently enough.
    # In case of doubts, do not touch the default 10s.
    node_update_check_interval: 10s

    # SQLite config
    db_type: sqlite3

    # For production:
    # db_path: /var/lib/headscale/db.sqlite
    db_path: ./db.sqlite

    # # Postgres config
    # If using a Unix socket to connect to Postgres, set the socket path in the 'host' field and leave 'port' blank.
    # db_type: postgres
    # db_host: localhost
    # db_port: 5432
    # db_name: headscale
    # db_user: foo
    # db_pass: bar

    # If other 'sslmode' is required instead of 'require(true)' and 'disabled(false)', set the 'sslmode' you need
    # in the 'db_ssl' field. Refers to https://www.postgresql.org/docs/current/libpq-ssl.html Table 34.1.
    # db_ssl: false

    ### TLS configuration
    #
    ## Let's encrypt / ACME
    #
    # headscale supports automatically requesting and setting up
    # TLS for a domain with Let's Encrypt.
    #
    # URL to ACME directory
    acme_url: https://acme-v02.api.letsencrypt.org/directory

    # Email to register with ACME provider
    acme_email: ""

    # Domain name to request a TLS certificate for:
    tls_letsencrypt_hostname: ""

    # Path to store certificates and metadata needed by
    # letsencrypt
    # For production:
    # tls_letsencrypt_cache_dir: /var/lib/headscale/cache
    tls_letsencrypt_cache_dir: ./cache

    # Type of ACME challenge to use, currently supported types:
    # HTTP-01 or TLS-ALPN-01
    # See [docs/tls.md](docs/tls.md) for more information
    tls_letsencrypt_challenge_type: HTTP-01
    # When HTTP-01 challenge is chosen, letsencrypt must set up a
    # verification endpoint, and it will be listening on:
    # :http = port 80
    tls_letsencrypt_listen: ":http"

    ## Use already defined certificates:
    tls_cert_path: ""
    tls_key_path: ""

    log:
      # Output formatting for logs: text or json
      format: text
      level: info

    # Path to a file containg ACL policies.
    # ACLs can be defined as YAML or HUJSON.
    # https://tailscale.com/kb/1018/acls/
    acl_policy_path: ""

    ## DNS
    #
    # headscale supports Tailscale's DNS configuration and MagicDNS.
    # Please have a look to their KB to better understand the concepts:
    #
    # - https://tailscale.com/kb/1054/dns/
    # - https://tailscale.com/kb/1081/magicdns/
    # - https://tailscale.com/blog/2021-09-private-dns-with-magicdns/
    #
    dns_config:
      # Whether to prefer using Headscale provided DNS or use local.
      override_local_dns: true

      # List of DNS servers to expose to clients.
      nameservers:
        - 1.1.1.1

      # NextDNS (see https://tailscale.com/kb/1218/nextdns/).
      # "abc123" is example NextDNS ID, replace with yours.
      #
      # With metadata sharing:
      # nameservers:
      #   - https://dns.nextdns.io/abc123
      #
      # Without metadata sharing:
      # nameservers:
      #   - 2a07:a8c0::ab:c123
      #   - 2a07:a8c1::ab:c123

      # Split DNS (see https://tailscale.com/kb/1054/dns/),
      # list of search domains and the DNS to query for each one.
      #
      # restricted_nameservers:
      #   foo.bar.com:
      #     - 1.1.1.1
      #   darp.headscale.net:
      #     - 1.1.1.1
      #     - 8.8.8.8

      # Search domains to inject.
      domains: []

      # Extra DNS records
      # so far only A-records are supported (on the tailscale side)
      # See https://github.com/juanfont/headscale/blob/main/docs/dns-records.md#Limitations
      # extra_records:
      #   - name: "grafana.myvpn.example.com"
      #     type: "A"
      #     value: "100.64.0.3"
      #
      #   # you can also put it in one line
      #   - { name: "prometheus.myvpn.example.com", type: "A", value: "100.64.0.3" }

      # Whether to use [MagicDNS](https://tailscale.com/kb/1081/magicdns/).
      # Only works if there is at least a nameserver defined.
      magic_dns: true

      # Defines the base domain to create the hostnames for MagicDNS.
      # `base_domain` must be a FQDNs, without the trailing dot.
      # The FQDN of the hosts will be
      # `hostname.user.base_domain` (e.g., _myhost.myuser.example.com_).
      base_domain: example.com

    # Unix socket used for the CLI to connect without authentication
    # Note: for production you will want to set this to something like:
    # unix_socket: /var/run/headscale.sock
    unix_socket: ./headscale.sock
    unix_socket_permission: "0770"
    #
    # headscale supports experimental OpenID connect support,
    # it is still being tested and might have some bugs, please
    # help us test it.
    # OpenID Connect
    # oidc:
    #   only_start_if_oidc_is_available: true
    #   issuer: "https://your-oidc.issuer.com/path"
    #   client_id: "your-oidc-client-id"
    #   client_secret: "your-oidc-client-secret"
    #   # Alternatively, set `client_secret_path` to read the secret from the file.
    #   # It resolves environment variables, making integration to systemd's
    #   # `LoadCredential` straightforward:
    #   client_secret_path: "${CREDENTIALS_DIRECTORY}/oidc_client_secret"
    #   # client_secret and client_secret_path are mutually exclusive.
    #
    #   # The amount of time from a node is authenticated with OpenID until it
    #   # expires and needs to reauthenticate.
    #   # Setting the value to "0" will mean no expiry.
    #   expiry: 180d
    #
    #   # Use the expiry from the token received from OpenID when the user logged
    #   # in, this will typically lead to frequent need to reauthenticate and should
    #   # only been enabled if you know what you are doing.
    #   # Note: enabling this will cause `oidc.expiry` to be ignored.
    #   use_expiry_from_token: false
    #
    #   # Customize the scopes used in the OIDC flow, defaults to "openid", "profile" and "email" and add custom query
    #   # parameters to the Authorize Endpoint request. Scopes default to "openid", "profile" and "email".
    #
    #   scope: ["openid", "profile", "email", "custom"]
    #   extra_params:
    #     domain_hint: example.com
    #
    #   # List allowed principal domains and/or users. If an authenticated user's domain is not in this list, the
    #   # authentication request will be rejected.
    #
    #   allowed_domains:
    #     - example.com
    #   # Note: Groups from keycloak have a leading '/'
    #   allowed_groups:
    #     - /headscale
    #   allowed_users:
    #     - alice@example.com
    #
    #   # If `strip_email_domain` is set to `true`, the domain part of the username email address will be removed.
    #   # This will transform `first-name.last-name@example.com` to the user `first-name.last-name`
    #   # If `strip_email_domain` is set to `false` the domain part will NOT be removed resulting to the following
    #   user: `first-name.last-name.example.com`
    #
    #   strip_email_domain: true

    # Logtail configuration
    # Logtail is Tailscales logging and auditing infrastructure, it allows the control panel
    # to instruct tailscale nodes to log their activity to a remote server.
    logtail:
      # Enable logtail for this headscales clients.
      # As there is currently no support for overriding the log server in headscale, this is
      # disabled by default. Enabling this will make your clients send logs to Tailscale Inc.
      enabled: false

    # Enabling this option makes devices prefer a random port for WireGuard traffic over the
    # default static port 41641. This option is intended as a workaround for some buggy
    # firewall devices. See https://tailscale.com/kb/1181/firewalls/ for more information.
    randomize_client_port: false

  roles:
    - hampusstrom.headscale
```

## Tags
### install
A complete installation and configuration of headscale and its namespaces.

### configure
Only updates the configuration file and/or systemd unit file.

### users
Only configures namespaces.

## License
MIT  [License](LICENSE)
