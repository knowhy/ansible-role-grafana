ansible-role-grafana
====================

[![Build Status](https://travis-ci.org/knowhy/ansible-role-grafana.svg?branch=master)](https://travis-ci.org/knowhy/ansible-role-grafana)

Ansible role to install Grafana metrics application.

Requirements
------------

- none

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`) and the comments / documentation from the `sample.ini` example configuration file. Variables which default to `[]` (null value) are not listed in `defaults/main.yml`. Parameters which need a type other than `string` or `integer` have a note with the required variable type.

	grafana_build: release

Build version to use. Valid values are `release` and `nightly`. Defaults to `release`.

	grafana_install_grafana: True

Install / Update Grafana application. Set to `False` to reconfigure Grafana and skip download and installation tasks. Boolean. Defaults to `True`.

	grafana_plugins: []

Install / Update Grafana plugins. List / Boolean. When list is set, defined plugins will be installed via `grafana-cli`. Set to `False` to skip installation of plugins.

	grafana_cleanup: False

Cleanup old Grafana versions under /opt. Boolean. Defaults to `False`.

	grafana_version: latest

Grafana version to install. `latest` or any version which describes a build `https://grafanarel.s3.amazonaws.com/builds/grafana-{{ grafana_version }}.linux-x64.tar.gz` is valid. Defaults to `latest`.

User for the Grafana process. Defaults to `grafana`.

	grafana_user: grafana

Group for the Grafana user. Defaults to `grafana`.

	grafana_group: grafana

Directory for Grafana application data. Defaults to `/usr/share/grafana`.

	grafana_home: /usr/share/grafana

Directory where grafana can store logs. Defaults to `/var/log/grafana`.

	grafana_log_dir: /var/log/grafana

Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used). Defaults to `/var/lib/grafana`.

	grafana_data_dir: /var/lib/grafana

Max open file limit for Grafana process. Defaults to `10000`.

	grafana_max_open_files: 10000

Path for Grafana configuration files. Defaults to `/etc/grafana`.

	grafana_conf_dir: /etc/grafana

Grafana ini configuration file. Defaults to `/etc/grafana/grafana.ini`.

	grafana_conf_file: /etc/grafana/grafana.ini

Controls whether to restart Grafana automatically when an update was installed. boolean. Defaults to `True`.

	grafana_restart_on_update: True

Directory where grafana will automatically scan and look for plugins. Defaults to `/var/lib/grafana/plugin`.

	grafana_plugins_dir: /var/lib/grafana/plugin

Timeout for Grafana server process. Defaults to `20`.

	grafana_timeout: 20

Protocol for Grafana web interfaces. Possible values `http` and `https`

	grafana_protocol: http

`No file` limit for Grafana process. Defaults to `1000`.

	grafana_limit_no_file: 10000

Controls start of Grafana process at boot. Boolean. Defaults to `False`.

	grafana_service_enabled: False

Controls whether to start Grafana process during executing of the play. Boolean. Defaults to `True`.

	grafana_service_start: True

Grafana app mode. Possible values: `production`, `development`. Defaults to `production`.

	grafana_app_mode: production

Instance name for the Grafana installation. Defaults to `HOSTNAME` environment variable value or hostname if HOSTNAME var is empty. Defaults to `${HOSTNAME}`.

	grafana_instance_name: ${HOSTNAME}

The ip address to bind to, empty will bind to all interfaces. Defaults to ` `.

	grafana_http_addr:

The http port to use. Defaults to `3000`.

	grafana_http_port: 3000

The public facing domain name used to access grafana from a browser. Defaults to `localhost`.

	grafana_domain: localhost

Redirect to correct domain if host header does not match domain. Prevents DNS rebinding attacks. Boolean. Defaults to `False`.

	grafana_enforce_domain: False

The full public facing url you use in browser, used for redirects and emails. If you use reverse proxy and sub path specify full url (with sub path). Defaults to `http://localhost:3000`.

	grafana_root_url: http://localhost:3000

Log web requests. Boolean. Defaults to `False`.

	grafana_router_logging: False

The path relative working path. Defaults to `public`.

	grafana_static_root_path: public

Enable `gzip` compression. Boolean. Defaults to `False`.

	grafana_enable_gzip: False

Path to certificate file for https. Defaults to ` `.

	grafana_cert_file:

Path to key file for https certificate. Defaults to ` `.

	grafana_key_file:

Type of database to use for Grafana internal database. Either `mysql`, `postgres` or `sqlite3`. Defaults to `sqlite3`.

	grafana_database: sqlite

Database host for Grafana internal database. Defaults to `127.0.0.1`.

	grafana_database_host: 127.0.0.1

Database port for Grafana internal database. Defaults to `3306`.

	grafana_database_port: 3306

Database name for Grafana internal database. Defaults to `grafana`.

	grafana_database_name: grafana

Database name for Grafana internal database. Defaults to `root`.

	grafana_database_user: root

Database password for Grafana internal database. Defaults to `password`.

	grafana_database_password: password

Database ssl_mode for Grafana internal database. For `postgres` only, either `disable`, `require` or `verify-full`. Defaults to `disable`.

	grafana_database_ssl_mode: disable

Path to sqlite3 database file. For "sqlite3" only, path relative to data_path setting. Defaults to `grafana.db`.

	grafana_database_path: grafana.db

Type of session provider. Either `memory`, `file`, `redis`, `mysql`, `postgres`. Defaults to `file`.

	grafana_session_provider: file

`file` provider config options. session dir path, is relative to grafana data_path. Defaults to ` `.

	grafana_session_provider_session_dir_path:

Redis server IP/DNS for `redis` session provider. Defaults to `127.0.0.1`.

	grafana_redis_address: 127.0.0.1

Redis port for `redis` session provider. Defaults to `6379`.

	grafana_redis_port: 6379

Redis pool size for `redis` session provider. Defaults to `100`.

	grafana_redis_pool_size: 100

Redis database name for `redis` session provider. Defaults to `grafana`.

	grafana_redis_database: grafana

MySQL user for MySQL session provider. Defaults to `user`.

	grafana_mysql_user: user

MySQL user password for MySQL session provider. Defaults to `password`.

	grafana_mysql_password: password

MySQL protocol for MySQL session provider. Defaults to `tcp`.

	grafana_mysql_protocol: tcp

MySQL address for MySQL session provider. Defaults to `127.0.0.1`.

	grafana_mysql_address: 127.0.0.1

MySQL `port` for MySQL session provider. Defaults to `3306`.

	grafana_mysql_port: 3306

MySQL `database name` for MySQL session provider. Defaults to `database_name`.

	grafana_mysql_database_name: database_name

Postgres `user` for postgress session provider. Defaults to `a`.

	grafana_postgres_user: a

Postgres `password` for postgress session provider. Defaults to `b`.

	grafana_postgres_password: b

Postgres `host` for postgress session provider. Defaults to `localhost`.

	grafana_postgres_host: localhost

Postgres `port` for postgress session provider. Defaults to `5432`.

	grafana_postgres_port: 5432

Postgres `database name` for postgress session provider. Defaults to `c`.

	grafana_postgres_database_name: c

Postgres `ssl_mode` for postgress session provider. Defaults to `disable`.

	grafana_postgres_sslmode: disable # disable or enable

Grafana provider config. Defaults to `sessions`.

	grafana_provider_config: sessions

Grafana cookie name. Defaults to `grafana_sess`

	grafana_cookie_name: grafana_sess

Use grafana cookie on in https sessions. Boolean. Defaults to `False`.

	grafana_cookie_secure: False

Grafana session life time in seconds. Defaults to `86400`.

	grafana_session_life_time: 86400

Server reporting, sends usage counters to stats.grafana.org every 24 hours. No ip addresses are being tracked, only simple counters to track running instances, dashboard and error counts. It is very helpful to us. Boolean. Defaults to `True`.

	grafana_analytics_reporting_enabled: True

Set to false to disable all checks to https://grafana.net for new vesions (grafana itself and plugins), check is used in some UI views to notify that grafana or plugin update exists. This option does not cause any auto updates, nor send any information only a GET request to http://grafana.net to get latest versions. Boolean. Defaults to `True`.

	grafana_analytics_check_for_updates: True

Google Analytics universal tracking code, only enabled if you specify an id here. Defaults to ` `.

	grafana_analytics_google_analytics_ua_id: ""

Default admin user, created on startup. Defaults to `admin`.

	grafana_security_default_admin_user: admin

Default admin password, can be changed before first start of grafana,  or in profile settings. Defaults to `admin`.

	grafana_security_admin_password: admin

Grafana security secret key used for signing. Defaults to `SW2YcwTIb9zpOOhoPsMm`.

	grafana_security_secret_key: SW2YcwTIb9zpOOhoPsMm

Auto-login remember days. Defaults to `7`.

	grafana_security_login_remember_days: 7

Username for Grafana security cookie. Defaults to `grafana_user`.

	grafana_security_cookie_username: grafana_user

Remember name for Grafana security cookie. Defaults to `grafana_remember`.

	grafana_security_cookie_remember_name: grafana_remember

Disable gravatar profile images. Boolean. Defaults to `False`.

	grafana_security_disable_gravatar: False

Data source proxy whitelist. List of dictonaries for data source proxy whitelist. Defaults to ` `.

	grafana_data_source_proxy_whitelist:
	-
	ip_domain:
	port:

Role for unauthenticated users. Defaults to `Viewer`.

	grafana_unauthenticated_users_role: Viewer

Enable Github authentication. Boolean. Defaults to `False`.

	grafana_auth_github_enabled: False

Allow signup for Github authenticated users. Boolean. Defaults to `True`.

	grafana_auth_github_allow_signup: True

Github client id. Defaults to `some_id`.

	grafana_auth_github_client_id: some_id

Github client secret. Defaults to `some_secret`.

	grafana_auth_github_client_secret: some_secret

Scopes for Github authentication. Defaults to `user:email,read:org`.

	grafana_auth_github_scopes: user:email,read:org

URL for for Github authentication. Defaults to `https://github.com/login/oauth/authorize`.

	grafana_auth_github_auth_url: https://github.com/login/oauth/authorize

Token URL for Github authentication. Defaults to `https://github.com/login/oauth/access_token`.

	grafana_auth_github_token_url: https://github.com/login/oauth/access_token

API URL for Github authentication. Defaults to `https://api.github.com/user`.

	grafana_auth_github_api_url: https://api.github.com/user

Team ids for Github authentication. Defaults to ` `.

	grafana_auth_github_team_ids:

Allowed organizations for Github authentication. Defaults to ` `.

	grafana_auth_github_allowed_organizations:

Enable Google authentication. Boolean. Defaults to `False`.

	grafana_auth_google_enable: False

Allow sign up for Google authentication. Boolean. Defaults to `True`.

	grafana_auth_google_allow_sign_up: True

Client id for Google authentication. Defaults to `some_client_id`.

	grafana_auth_google_client_id: some_client_id

Client secret for Google authentication. Defaults to `some_client_secret`.

	grafana_auth_google_client_secret: some_client_secret

Scopes for Google authentication. Defaults to `https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email`.

	grafana_auth_google_scopes: https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email

Authentication URL for Google authentication. Defaults to `https://accounts.google.com/o/oauth2/auth`.

	grafana_auth_google_auth_url: https://accounts.google.com/o/oauth2/auth

Token URL for Google authentication. Defaults to `https://accounts.google.com/o/oauth2/token`.

	grafana_auth_google_token_url: https://accounts.google.com/o/oauth2/token

API URL for Google authentication. Defaults to `https://www.googleapis.com/oauth2/v1/userinfo`.

	grafana_auth_google_api_url: https://www.googleapis.com/oauth2/v1/userinfo

Allowed domains for Google authentication. Defaults to ` `.

	grafana_auth_google_allowed_domains:

Enable generic oauth authentication. Boolean. Defaults to `False`.

	grafana_auth_generic_oauth_enabled: False

Name for generic oauth authentication. Defaults to `OAuth`.

	grafana_auth_generic_oauth_name: OAuth

Allow sign up for generic oauth authentication. Boolean. Defaults to `True`.

	grafana_auth_generic_oauth_allow_sign_up: True

Client id generic for oauth authentication. Defaults to `some_id`.

	grafana_auth_generic_oauth_client_id: some_id

Client secret generic for oauth authentication. Defaults to `some_secret`.

	grafana_auth_generic_oauth_client_secret: some_secret

Scope for generic oauth authentication. Defaults to `user:email,read:org`.

	grafana_auth_generic_oauth_scopes: user:email,read:org

Authentication URL for generic oauth authentication. Defaults to `https://foo.bar/login/oauth/authorize`.

	grafana_auth_generic_oauth_auth_url: https://foo.bar/login/oauth/authorize

Token URL for generic oauth authentication. Defaults to `https://foo.bar/login/oauth/access_token`.

	grafana_auth_generic_oauth_token_url: https://foo.bar/login/oauth/access_token

API URL for generic oauth authentication. Defaults to `https://foo.bar/user`.

	grafana_auth_generic_oauth_api_url: https://foo.bar/user

Team ids for generic oauth authentication. Defaults to ` `.

	grafana_auth_generic_oauth_team_ids:

Allowed organizations for generic oauth authentication. Defaults to ` `.

	grafana_auth_generic_oauth_allowed_organizations:

Enable grafananet authentication. Boolean. Defaults to `False`.

	grafana_auth_grafananet_enabled: False

Allow sign up for grafananet authentication. Boolean. Defaults to `True`.

	grafana_auth_grafananet_allow_sign_up: True

Client id for grafananet authentication. Defaults to `some_id`.

	grafana_auth_grafananet_client_id: some_id

Client secret for grafananet authentication. Defaults to `some_secret`.

	grafana_auth_grafananet_client_secret: some_secret

Scopes for grafananet authentication. Defaults to `user:email`.

	grafana_auth_grafananet_scopes: user:email

Allowed organizations for grafananet authentication. Defaults to ` `.

	grafana_auth_grafananet_allowed_organizations:

Enable proxy authentication. Boolean. Defaults to `False`.

	grafana_auth_proxy_enabled: False

Header name for proxy authentication. Defaults to `X-WEBAUTH-USER`.

	grafana_auth_proxy_header_name: X-WEBAUTH-USER

Header property for proxy authentication. Defaults to `username`.

	grafana_auth_proxy_header_property: username

Enable auto sign up for proxy authentication. Boolean. Defaults to `True`.

	grafana_auth_proxy_auto_sign_up: True

LDAP sync TTL for proxy authentication. Defaults to ` `.

	grafana_auth_proxy_ldap_sync_ttl:

Whitelist for proxy authentication. Defaults to `192.168.1.1, 192.168.2.1`.

	grafana_auth_proxy_whitelist: "192.168.1.1, 192.168.2.1"

Enable basic authentication. Boolean. Defaults to `True`.

	grafana_auth_basic_enabled: True

Enable LDAP authentication. Boolean. Defaults to `False`.

	grafana_auth_ldap_enabled: False

LDAP config file for LDAP authentication. Defaults to `/etc/grafana/ldap.toml`.

	grafana_auth_ldap_config_file: /etc/grafana/ldap.toml

Allow sign up for LDAP authentication. Boolean. Defaults to `True`.

	grafana_auth_ldap_allow_sign_up: True

Enable SMTP. Boolean. Defaults to `False`.

	grafana_smtp_enabled: False

SMTP host. Defaults to `localhost:25`.

	grafana_smtp_host: localhost:25

Username for SMTP. Defaults to ` `.

	grafana_smtp_user:

Password for SMTP. Defaults to ` `.

	grafana_smtp_password:

Certificate file for SMTP. Defaults to ` `.

	grafana_smtp_cert_file:

Keyfile for SMTP. Defaults to ` `.

	grafana_smtp_key_file:

Skip verification for SMTP. Boolean. Defaults to `False`.

	grafana_smtp_skip_verify: False

`From address` for SMTP. Defaults to `admin@grafana.localhost`.

	grafana_smtp_from_address: admin@grafana.localhost

Send Grafana welcome email. Boolean. Defaults to `False`.

	grafana_emails_welcome_email: False

Log modes. List. Either `console`, `file`, `syslog`. Defaults to `console` and `file`.

	grafana_log_mode:
	- console
	- file

Log level. Either `trace`, `debug`, `info`, `warn`, `error`, `critical`. Defaults to `info`.

	grafana_log_level: info

optional settings to set different levels for specific loggers. Ex. `filters = sqlstore:debug`. Defaults to ` `.

	grafana_log_filters:

Log level for `console` mode only. Defaults to ` `.

	grafana_log_console_level:

Log line format for console log. Valid options are `text`, `console` and `json`. Defaults to `console`.

	grafana_log_console_format: console

Log level for log file mode. Defaults to ` `.

	grafana_log_file_level:

Log line formt for file log. Valid options are text, console and json. Defaults to `text`.

	grafana_log_file_line_format: text

Enable automated log rotate. Boolean. Defaults to `True`.

	grafana_log_file_log_rotate: True

Max line number of single file, Defaults to `1000000`.

	grafana_log_file_max_lines: 1000000

Max size shift of single file, default is `28` means `1 << 28, 256MB`. Defaults to `28`.

	grafana_log_file_max_size_shift: 28

Segment log daily. Boolean. Defaults to `True`.

	grafana_log_file_daily_rotate: True

Expired days of log file (delete after max days). Defaults to `7`.

	grafana_log_file_max_days: 7

Log level for syslog. Defaults to ` `.

	grafana_log_syslog_level:

Log line format for syslog log. Valid options are `text`, `console` and `json`. Defaults to `text`.

	grafana_log_syslog_format: text

Syslog network type and address. This can be `udp`, `tcp`, or `unix`. If left blank, the default unix endpoints will be used. Defaults to ` `.

	grafana_log_syslog_network:

Syslog address. Defaults to ` `.

	grafana_log_syslog_address:

Syslog facility. user, daemon and local0 through local7 are valid. Defaults to ` `.

	grafana_log_syslog_facility:

Syslog tag. By default, the process `argv[0]` is used. Defaults to ` `.

	grafana_log_syslog_tag:

Enable AMQP Event Publisher. Boolean. Defaults to `False`.

	grafana_event_publisher_enabled: False

AMQP Event Publisher URL. Defaults to `amqp://localhost/`.

	grafana_event_publisher_url: amqp://localhost/

AMQP Event Publisher exchange. Defaults to `grafana_events`.

	grafana_event_publisher_exchange: grafana_events

Enable Dashboard JSON files. Boolean. Defaults to `False`.

	grafana_dashboards_json_enabled: False

Path to grafana dashboards. Defaults to `/var/lib/grafana/dashboards`.

	grafana_dashboards_json_path: /var/lib/grafana/dashboards

Enable alert rule execution. Boolean. Defaults to `True`.

	grafana_altering_execute_alerts: True

Enable internal metrics available at HTTP API Url /api/metrics. Boolean. Defaults to `True`.

	grafana_metrics_enabled: True

Publish interval. Defaults to `10`.

	grafana_publish_interval: 10

Send internal metrics to Graphite. Enable by setting the address setting (ex localhost:2003). Defaults to ` `.

	grafana_metrics_graphite_address:

Graphite prefix. Defaults to `prod.grafana.%(instance_name)s.`.

	grafana_metrics_graphite_prefix: prod.grafana.%(instance_name)s.

grafana_net URL. Url used to to import dashboards directly from Grafana.net. Defaults to `https://grafana.net`.

	grafana_grafana_net_url: https://grafana.net

External image storage provider. Used for uploading images to public servers so they can be included in slack/email messages. You can choose between (`s3`, `webdav`). Defaults to ` `.

	grafana_external_image_storage_provider:

Bucket URL for S3 external image storage. Defaults to ` `.

	grafana_external_image_storage_s3_bucket_url:

Access key for S3 external image storage. Defaults to ` `.

	grafana_external_image_storage_s3_access_key:

Secret key for S3 external image storage. Defaults to ` `.

	grafana_external_image_storage_s3_secret_key:

URL for WebDAV external image storage. Defaults to ` `.

	grafana_external_image_storage_webdav_url:

Username for WebDAV external image storage. Defaults to ` `.

	grafana_external_image_storage_webdav_username:

Password for WebDAV external image storage. Defaults to ` `.

	grafana_external_image_storage_webdav_password:

Dependencies
------------

none

Notes
-----

This role installs Grafana using the builds provided under `https://grafanarel.s3.amazonaws.com/builds/grafana-{{ grafana_version }}.linux-x64.tar.gz` for nightly builds and `https://s3-us-west-2.amazonaws.com/grafana-releases/master/grafana-{{ grafana_version }}.linux-x64.tar.gz.sha256` for release builds.

This role is tested against `CentOS 7`, `Ubuntu 16.04` and `Ubuntu 14.04` but it should work on any Linux distribution as there are no distribution specific dependencies.

Support for for `upstart` init script is currently not tested.

Example Playbook
----------------

    - hosts: servers
      roles:
         - { role: knowhy.grafana }

License
-------

GNU AGPLv3

Author Information
------------------

This role was created in 2017 by Henrik Pingel.
