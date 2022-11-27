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
If a setting corresponds to a setting in the headscale configuration file it will be followed by the name of the section in which the setting resides (if any), followed by the setting name.

`headscale_[section-if-any]_[setting_name]`

### Custom Settings
On top of providing you the ability to configure all of the default values in the headscale configuration file, this role also provides you a couple of extra settings.

#### **headscale_version**

Defines the version of headscale to download and install on the target machines.
Can be either a version number (without 'v' prefix). I.e. **0.16.4** or **latest**

Latest will automatically retrieve the latest release tag from the [juanfont/headscale](https://github.com/juanfont/headscale) Github repository.


default: `latest`

#### **headscale_github_repository**
Defines the user/repo to use when looking for and downloading the headscale binary.
Can be changed to another repo to allow installations of forks for example.

default:`juanfont/headscale`

#### **headscale_binary_path**

Defines where the headscale binary will be downloaded and installed to.

default: `/usr/local/bin/headscale`

#### **headscale_user_name**
Defines the name of the system user that should run the headscale systemd daemon.
Will be created if it not already exists.

default: `headscale`

#### **headscale_user_id**
Defines the user ID of the `headscale_user_name` user.

default: `1111`

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
Should be the same directory as `headscale_unix_socket` points to.

default: `/var/run/headscale`

## Example Playbook
```yaml
---

- hosts: headscale
  become: yes
  vars_files:
    - your_config_file.yaml
  roles:
    - hampusstrom.headscale

```
Inside `your_config_file.yaml`
```yaml
---
# The url that clients will use to connect. Must include :port number suffix
headscale_server_url: https://headscale.example.com:443

# if headscale_listen_addr is not defined, the server will only listen to connection from localhost.
headscale_listen_addr: 0.0.0.0:443

# When using the 'latest' tag,
# the role will automatically try to get the latest release tag from GitHub repo juanfont/Headscale
# this is not always going to work like when the authors release a new beta version,
# and if you run this role a lot you might hit the GitHub API rate limit
# if you want stability I recommend tagging a specific release version, without the 'v' prefix.
# I.e. 'v0.16.4' should be defined as '0.16.4'
# headscale_version: 0.16.4
headscale_version: latest

# Minimum settings required to get acme certificate automatically through headscale
# Note: The default acme challenge is HTTP-01, which requires port 80/TCP to be open.
headscale_acme_email: admin@example.com
headscale_tls_letsencrypt_hostname: headscale.example.com
```

## License
MIT / BSD [License](LICENSE)