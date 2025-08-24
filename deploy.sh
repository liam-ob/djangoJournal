#!/bin/bash

# Exit on any error
set -e

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
}

if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
    log "UFW is active. Allowing HTTP and HTTPS traffic."
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
fi

# Check if nginx is installed
if ! command -v nginx >/dev/null 2>&1; then
    error "nginx is not installed or not in PATH, please install before deploying"
    exit 1
fi

# Check if gunicorn is installed
if ! command -v gunicorn >/dev/null 2>&1; then
    error "gunicorn is not installed or not in PATH, please install before deploying"
    exit 1
fi

# Check if certbot is installed
if ! command -v certbot >/dev/null 2>&1; then
    error "certbot is not installed or not in PATH, please install before deploying"
    exit 1
fi

# Get user inputs
echo "Enter the name of your application (no whitespaces please):"
read -r app_name
if [[ -z "$app_name" || "$app_name" =~ [[:space:]] ]]; then
    error "Invalid app name. Must not be empty or contain spaces."
    exit 1
fi

echo "Enter your domain name (e.g., myapp.example.com):"
read -r domain_name
if [[ -z "$domain_name" ]]; then
    error "Domain name cannot be empty"
    exit 1
fi

echo "Enter your email address for Let's Encrypt notifications:"
read -r CERTBOT_EMAIL
if [[ ! "$CERTBOT_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    error "Invalid email address format"
    exit 1
fi

# Get the nginx user
get_nginx_user() {
    local nginx_user=""
    
    # Method 1: Check nginx configuration for 'user' directive
    if command -v nginx >/dev/null 2>&1; then
        nginx_user=$(nginx -T 2>/dev/null | grep -m1 "^user " | awk '{print $2}' | sed 's/;//' || true)
    fi
    
    # Method 2: If not found in config, check running processes
    if [[ -z "$nginx_user" ]]; then
        nginx_user=$(ps aux | grep "nginx: worker process" | grep -v grep | head -1 | awk '{print $1}' || true)
    fi
    
    # Method 3: Check common default users if still not found
    if [[ -z "$nginx_user" ]]; then
        if id www-data >/dev/null 2>&1; then
            nginx_user="www-data"
        elif id nginx >/dev/null 2>&1; then
            nginx_user="nginx"
        elif id http >/dev/null 2>&1; then
            nginx_user="http"
        fi
    fi
    
    echo "$nginx_user"
}

NGINX_USER=$(get_nginx_user)

if [[ -z "$NGINX_USER" ]]; then
    error "Could not determine nginx user. Please check your nginx installation."
    exit 1
fi

log "Detected nginx user: $NGINX_USER"

# Check if app user already exists
if id "$app_name" >/dev/null 2>&1; then
    log "User $app_name already exists, skipping user creation"
else
    log "Creating app user: $app_name"
    sudo useradd -r -s /bin/false "$app_name"
fi

# Make app directory
log "Setting up application directory"
sudo mkdir -p "/var/www/$app_name"
sudo chown "$app_name:$app_name" "/var/www/$app_name"
sudo chmod 755 "/var/www/$app_name"

# Set up socket group so that the nginx user and app user can both communicate
app_socket_group="${app_name}_socket"
if ! getent group "$app_socket_group" >/dev/null 2>&1; then
    log "Creating socket group: $app_socket_group"
    sudo groupadd "$app_socket_group"
else
    log "Socket group $app_socket_group already exists"
fi

# Create socket folder
sudo mkdir -p "/var/www/$app_socket_group"
sudo chown "$app_name:$app_socket_group" "/var/www/$app_socket_group"
sudo chmod 750 "/var/www/$app_socket_group"

# Add app user and nginx user to app socket group
log "Adding users to socket group"
sudo usermod -a -G "$app_socket_group" "$NGINX_USER"
sudo usermod -a -G "$app_socket_group" "$app_name"

# Set up the logs directory
log "Setting up logs directory"
sudo mkdir -p "/var/www/$app_name/logs"
sudo chown "$app_name:$app_name" "/var/www/$app_name/logs"
sudo chmod 755 "/var/www/$app_name/logs"

# Create static directory
log "Setting up static directory"
sudo mkdir -p "/var/www/$app_name/static"
sudo chown "$app_name:$app_name" "/var/www/$app_name/static"
sudo chmod 755 "/var/www/$app_name/static"

# Create a systemd file for socket management, not completemly neccessary but nice to have
log "Creating systemd socket file"
sudo tee "/etc/systemd/system/$app_name.socket" > /dev/null <<EOF
[Unit]
Description=$app_name socket

[Socket]
ListenStream=/var/www/$app_socket_group/$app_name.sock
SocketUser=$app_name
SocketGroup=$app_socket_group
SocketMode=0660

[Install]
WantedBy=sockets.target
EOF

# Create systemctl daemon file
log "Creating systemd service file"
sudo tee "/etc/systemd/system/$app_name.service" > /dev/null <<EOF
[Unit]
Description=$app_name Web Application
Requires=$app_name.socket
After=network.target

[Service]
User=$app_name
Group=$app_name
WorkingDirectory=/var/www/$app_name
Restart=always
RestartSec=10

ExecStart=$(command -v gunicorn) \\
        --access-logfile /var/www/$app_name/logs/gunicorn-access.log \\
        --error-logfile /var/www/$app_name/logs/gunicorn-error.log \\
        --workers 1 \\
        $app_name.wsgi:application

# Environment variables
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Create initial nginx conf (HTTP only for certificate generation)
log "Creating initial nginx configuration (HTTP only)"
sudo tee "/etc/nginx/sites-available/${app_name}.${domain_name}" > /dev/null <<EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=${app_name}_limit:10m rate=5r/s;

log_format ${app_name}_main '\$status - [\$time_local] \$host \\t - \$remote_addr \\t '
                    '\$body_bytes_sent \\t "\$request" | REFERER:"\$http_referer" '
                    '| AGENT:"\$http_user_agent" | FORWARD:"\$http_x_forwarded_for"';

server {
    listen 80;
    server_name $domain_name;
    
    access_log /var/www/$app_name/logs/access.log ${app_name}_main;
    error_log /var/www/$app_name/logs/error.log;
    
    # Temporary location for Let's Encrypt challenges
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location /static/ {
        alias /var/www/$app_name/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Main application
    location / {
        include /etc/nginx/mime.types;
        proxy_pass http://unix:/var/www/$app_socket_group/$app_name.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Apply rate limiting
        limit_req zone=${app_name}_limit burst=10 nodelay;
    }
    
    client_max_body_size 10M;
    client_body_timeout 30s;
    client_header_timeout 30s;
}
EOF

# Link the file into sites-enabled
if [[ ! -L "/etc/nginx/sites-enabled/${app_name}.${domain_name}" ]]; then
    log "Enabling nginx site"
    sudo ln -s "/etc/nginx/sites-available/${app_name}.${domain_name}" "/etc/nginx/sites-enabled/${app_name}.${domain_name}"
fi

# Test nginx configuration
log "Testing nginx configuration"
if ! sudo nginx -t; then
    error "Nginx configuration test failed"
    exit 1
fi

# Ensure nginx is running for the HTTP-01 challenge
log "Starting/restarting nginx"
sudo systemctl restart nginx
sudo systemctl enable nginx

# Create webroot directory for challenges
sudo mkdir -p /var/www/html
sudo chown "$NGINX_USER:$NGINX_USER" /var/www/html

# perform dry run to test the setup
if ! sudo certbot certonly --webroot --webroot-path=/var/www/html --email "$CERTBOT_EMAIL" --agree-tos --no-eff-email -d "$domain_name" --dry-run; then
    error "Certbot dry run failed. Please check your DNS and Nginx configuration."
    exit 1
fi

# Get SSL certificate
log "Obtaining SSL certificate from Let's Encrypt"
if sudo certbot certonly \
    --webroot \
    --webroot-path=/var/www/html \
    --email "$CERTBOT_EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$domain_name"; then
    
    log "SSL certificate obtained successfully"
    
    # Update nginx config to enable SSL
    log "Updating nginx configuration with SSL"
    sudo tee "/etc/nginx/sites-available/${app_name}.${domain_name}" > /dev/null <<EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=${app_name}_limit:10m rate=5r/s;

log_format ${app_name}_main '\$status - [\$time_local] \$host \\t - \$remote_addr \\t '
                    '\$body_bytes_sent \\t "\$request" | REFERER:"\$http_referer" '
                    '| AGENT:"\$http_user_agent" | FORWARD:"\$http_x_forwarded_for"';

server {
    listen 443 ssl http2;
    server_name $domain_name;
    
    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/$domain_name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain_name/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$domain_name/chain.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    access_log /var/www/$app_name/logs/access.log ${app_name}_main;
    error_log /var/www/$app_name/logs/error.log;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;
    
    location /static/ {
        alias /var/www/$app_name/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Main application
    location / {
        include /etc/nginx/mime.types;
        proxy_pass http://unix:/var/www/$app_socket_group/$app_name.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Apply rate limiting
        limit_req zone=${app_name}_limit burst=10 nodelay;
    }
    
    client_max_body_size 10M;
    client_body_timeout 30s;
    client_header_timeout 30s;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name $domain_name;
    
    # Allow Let's Encrypt challenges
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect everything else to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
    
    # Test nginx config
    log "Testing updated nginx configuration"
    if sudo nginx -t; then
        log "Reloading nginx with SSL configuration"
        sudo systemctl reload nginx
    else
        error "Nginx configuration test failed after SSL setup"
        exit 1
    fi
    

    # Enable and start the application socket
    log "Enabling and starting the application socket"
    sudo systemctl daemon-reload
    sudo systemctl enable "$app_name.socket"
    sudo systemctl start "$app_name.socket"
    
    log "Deployment completed successfully!"
    log "Your application should be accessible at: https://$domain_name"
    log ""
    log "Next steps:"
    log "1. Copy your application code to: /var/www/$app_name/"
    log "2. Install your Python dependencies in the application directory"
    log "3. The service will start automatically on the first request."
    log "4. Check socket status: sudo systemctl status $app_name.socket"
    log "5. Check service status: sudo systemctl status $app_name.service"
    log "6. View logs: sudo journalctl -u $app_name -f"
    
else
    error "SSL certificate setup failed."
    exit 1
fi