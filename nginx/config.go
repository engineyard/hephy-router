package nginx

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/teamhephy/router/model"
)

const (
	confTemplate = `daemon off;
pid /tmp/nginx.pid;
worker_processes auto;



events {
	worker_connections 768;
	# multi_accept on;
}

http {
	# basic settings
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;

	vhost_traffic_status_zone shared:vhost_traffic_status:1m;

	# The timeout value must be greater than the front facing load balancers timeout value.
	# Default is the deis recommended timeout value for ELB - 1200 seconds + 100s extra.
	keepalive_timeout 1300s;

	types_hash_max_size 2048;
	server_names_hash_max_size 4096;
	server_names_hash_bucket_size 512;

	gzip on;
	gzip_comp_level 5;
	gzip_disable msie6;
	gzip_http_version 1.1;
	gzip_min_length 256;
	gzip_types application/atom+xml application/javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/svg+xml image/x-icon text/css text/plain text/x-component;
	gzip_proxied any;
	gzip_vary on;

	client_max_body_size 1m;
	large_client_header_buffers 4 32k;


	set_real_ip_from 64.252.64.0/18;
	set_real_ip_from 64.252.128.0/18;
	set_real_ip_from 10.0.0.0/8;
	real_ip_recursive on;
	real_ip_header X-Forwarded-For;

	log_format upstreaminfo '[$time_iso8601] - $app_name - $remote_addr - $remote_user - $status - "$request" - $bytes_sent - "$http_referer" - "$http_user_agent" - "$server_name" - $upstream_addr - $http_host - $upstream_response_time - $request_time';

	access_log /tmp/logpipe upstreaminfo;
	error_log  /tmp/logpipe error;

	map $http_upgrade $connection_upgrade {
		default upgrade;
		'' close;
	}

	# The next two maps work together to determine the $access_scheme:
	# 1. Determine if SSL may have been offloaded by the load balancer, in such cases, an HTTP request should be
	# treated as if it were HTTPs.
	map $http_x_forwarded_proto $tmp_access_scheme {
		default $scheme;               # if X-Forwarded-Proto header is empty, $tmp_access_scheme will be the actual protocol used
		"~^(.*, ?)?http$" "http";      # account for the possibility of a comma-delimited X-Forwarded-Proto header value
		"~^(.*, ?)?https$" "https";    # account for the possibility of a comma-delimited X-Forwarded-Proto header value
		"~^(.*, ?)?ws$" "ws";      # account for the possibility of a comma-delimited X-Forwarded-Proto header value
		"~^(.*, ?)?wss$" "wss";    # account for the possibility of a comma-delimited X-Forwarded-Proto header value
	}
	# 2. If the request is an HTTPS/wss request, upgrade $access_scheme to https/wss, regardless of what the X-Forwarded-Proto
	# header might say.
	map $scheme $access_scheme {
		default $tmp_access_scheme;
		"https" "https";
		"wss"	"wss";
	}

	# Determine the forwarded port:
	# 1. First map the unprivileged ports that Nginx (as a non-root user) actually listen on to the
	# familiar, equivalent privileged ports. (These would be the ports the k8s service listens on.)
	map $server_port $standard_server_port {
		default $server_port;
		8080 80;
		6443 443;
	}
	# 2. If the X-Forwarded-Port header has been set already (e.g. by a load balancer), use its
	# value, otherwise, the port we're forwarding for is the $standard_server_port we determined
	# above.
	map $http_x_forwarded_port $forwarded_port {
		default $http_x_forwarded_port;
		'' $standard_server_port;
	}
	# uri_scheme will be the scheme to use when the ssl is enforced.
	map $access_scheme $uri_scheme {
		default "https";
		"ws"	"wss";
	}





	# Only allow early data (TLSv1.3 0-RTT) for select methods
	map $request_method $ssl_block_early_data {
		default $ssl_early_data;
		"~^GET|HEAD|OPTIONS$" 0;
	}










	# Default server handles requests for unmapped hostnames, including healthchecks
	server {
		listen 8652 default_server reuseport;
		listen 6443 default_server ssl http2 ;

		# set header size limits
		 http2_max_header_size 32k;
		 http2_max_field_size  16k;

		set $app_name "router-default-vhost";
		ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
		ssl_ciphers [TLS_AES_128_GCM_SHA256|TLS_CHACHA20_POLY1305_SHA256]:TLS_AES_256_GCM_SHA384:[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305|ECDHE-ECDSA-CHACHA20-POLY1305-OLD]:[ECDHE-RSA-AES128-GCM-SHA256|ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-CHACHA20-POLY1305-OLD]:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA;
		ssl_prefer_server_ciphers on;
		ssl_early_data on;

		ssl_certificate /opt/router/ssl/platform.crt;
		ssl_certificate_key /opt/router/ssl/platform.key;


		ssl_session_tickets on;
		ssl_buffer_size 4k;
		ssl_dhparam /opt/router/ssl/dhparam.pem;

		server_name google.com;
		location ~ ^/healthz/?$ {
			access_log off;
			default_type 'text/plain';
			return 200;
		}
		location / {
			return 404;
		}
	}


	# Healthcheck on 9090 -- never uses proxy_protocol
	server {
		listen 9090 default_server;
		server_name _;
		set $app_name "router-healthz";
		location ~ ^/healthz/?$ {
			access_log off;
			default_type 'text/plain';
			return 200;
		}
		location ~ ^/stats/?$ {
			vhost_traffic_status_display;
			vhost_traffic_status_display_format json;
			allow 127.0.0.1;
			deny all;
		}
	 	location /nginx_status {
      			stub_status on;
		      	allow 127.0.0.1;
		      	deny all;
		}
		location / {
			return 404;
		}
	}



	server {

		listen 8080 default_server;
		server_name ~.;
		server_name_in_redirect off;
		port_in_redirect off;
		set $app_name "konimbo-stage";
		proxy_set_header Connection "";




		# set header size limits
		 http2_max_header_size 32k;
		 http2_max_field_size  16k;





		vhost_traffic_status_filter_by_set_key konimbo-stage application::*;

		if ($ssl_block_early_data) {
			return 425;
		}


			location / {





				proxy_buffering off;
				proxy_buffer_size 4k;
				proxy_buffers 8 4k;
				proxy_busy_buffers_size 8k;
				proxy_set_header Host $host;
				proxy_set_header X-Forwarded-For $remote_addr;
				proxy_set_header X-Forwarded-Proto $access_scheme;
				proxy_set_header X-Forwarded-Port $forwarded_port;
				proxy_redirect off;
				proxy_connect_timeout 30s;
				proxy_send_timeout 1300s;
				proxy_read_timeout 1300s;
				proxy_http_version 1.1;
				proxy_set_header Upgrade $http_upgrade;
				proxy_set_header Connection $connection_upgrade;
				proxy_set_header Early-Data $ssl_early_data;







				proxy_pass http://konimbo-stage.konimbo-stage:80;
			}



	}

server {
		listen 8080 proxy_protocol;
		server_name ~^eyk\.(?<domain>.+)$;
		server_name_in_redirect off;
		port_in_redirect off;
		set $app_name "deis/deis-controller";
                proxy_set_header Connection "";



		# set header size limits
		 http2_max_header_size 32k;
		 http2_max_field_size  16k;


		listen 6443 ssl http2 proxy_protocol;
		ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
		ssl_ciphers [TLS_AES_128_GCM_SHA256|TLS_CHACHA20_POLY1305_SHA256]:TLS_AES_256_GCM_SHA384:[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305|ECDHE-ECDSA-CHACHA20-POLY1305-OLD]:[ECDHE-RSA-AES128-GCM-SHA256|ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-CHACHA20-POLY1305-OLD]:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA;
		ssl_prefer_server_ciphers on;
		ssl_early_data on;
		ssl_certificate /opt/router/ssl/eyk.crt;
		ssl_certificate_key /opt/router/ssl/eyk.key;

		ssl_session_tickets on;
		ssl_buffer_size 4k;
		ssl_dhparam /opt/router/ssl/dhparam.pem;





		vhost_traffic_status_filter_by_set_key deis/deis-controller application::*;

		if ($ssl_block_early_data) {
			return 425;
		}


			location / {





				proxy_buffering off;
				proxy_buffer_size 4k;
				proxy_buffers 8 4k;
				proxy_busy_buffers_size 8k;
				proxy_set_header Host $host;
				proxy_set_header X-Forwarded-For $remote_addr;
				proxy_set_header X-Forwarded-Proto $access_scheme;
				proxy_set_header X-Forwarded-Port $forwarded_port;
				proxy_redirect off;
				proxy_connect_timeout 10;
				proxy_send_timeout 1200;
				proxy_read_timeout 1200;
				proxy_http_version 1.1;
				proxy_set_header Upgrade $http_upgrade;
				proxy_set_header Connection $connection_upgrade;
				proxy_set_header Early-Data $ssl_early_data;







				proxy_pass http://deis-controller:80;
			}


		}	


}

stream {
	server {
		listen 2222 ;
		proxy_connect_timeout 10s;
		proxy_timeout 1200s;
		proxy_pass deis-builder:2222;
	}
}`
)

// WriteCerts writes SSL certs to file from router configuration.
func WriteCerts(routerConfig *model.RouterConfig, sslPath string) error {
	// Start by deleting all certs and their corresponding keys. This will ensure certs we no longer
	// need are deleted. Certs that are still needed will simply be re-written.
	allCertsGlob, err := filepath.Glob(filepath.Join(sslPath, "*.crt"))
	if err != nil {
		return err
	}
	allKeysGlob, err := filepath.Glob(filepath.Join(sslPath, "*.key"))
	if err != nil {
		return err
	}
	for _, cert := range allCertsGlob {
		if err := os.Remove(cert); err != nil {
			return err
		}
	}
	for _, key := range allKeysGlob {
		if err := os.Remove(key); err != nil {
			return err
		}
	}
	if routerConfig.PlatformCertificate != nil {
		err = writeCert("platform", routerConfig.PlatformCertificate, sslPath)
		if err != nil {
			return err
		}
	}
	for _, appConfig := range routerConfig.AppConfigs {
		for domain, certificate := range appConfig.Certificates {
			if certificate != nil {
				err = writeCert(domain, certificate, sslPath)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeCert(context string, certificate *model.Certificate, sslPath string) error {
	certPath := filepath.Join(sslPath, fmt.Sprintf("%s.crt", context))
	keyPath := filepath.Join(sslPath, fmt.Sprintf("%s.key", context))
	err := ioutil.WriteFile(certPath, []byte(certificate.Cert), 0644)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(keyPath, []byte(certificate.Key), 0600)
}

// WriteDHParam writes router DHParam to file from router configuration.
func WriteDHParam(routerConfig *model.RouterConfig, sslPath string) error {
	dhParamPath := filepath.Join(sslPath, "dhparam.pem")
	if routerConfig.SSLConfig.DHParam == "" {
		err := os.RemoveAll(dhParamPath)
		if err != nil {
			return err
		}
	} else {
		err := ioutil.WriteFile(dhParamPath, []byte(routerConfig.SSLConfig.DHParam), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteConfig dynamically produces valid nginx configuration by combining a Router configuration
// object with a data-driven template.
func WriteConfig(routerConfig *model.RouterConfig, filePath string) error {
	tmpl, err := template.New("nginx").Funcs(sprig.TxtFuncMap()).Parse(confTemplate)
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	err = tmpl.Execute(file, routerConfig)
	return err
}

