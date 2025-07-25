#!/bin/bash

# EC2 Deployment Script for LangChain Security Bot
echo "🚀 Starting EC2 deployment for LangChain Security Bot..."

# Update system
echo "📦 Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and pip
echo "🐍 Installing Python and pip..."
sudo apt-get install -y python3 python3-pip python3-venv

# Install nginx for reverse proxy
echo "🌐 Installing nginx..."
sudo apt-get install -y nginx

# Create application directory
echo "📁 Setting up application directory..."
sudo mkdir -p /opt/security-bot
sudo chown $USER:$USER /opt/security-bot

# Copy application files
echo "📋 Copying application files..."
cp -r . /opt/security-bot/
cd /opt/security-bot

# Create virtual environment
echo "🔧 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn

# Create systemd service file
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/security-bot.service > /dev/null <<EOF
[Unit]
Description=LangChain Security Bot
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/security-bot
Environment=PATH=/opt/security-bot/venv/bin
ExecStart=/opt/security-bot/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:3000 main:flask_app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx
echo "🌐 Configuring nginx..."
sudo tee /etc/nginx/sites-available/security-bot > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable nginx site
sudo ln -sf /etc/nginx/sites-available/security-bot /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Start services
echo "🚀 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable security-bot
sudo systemctl start security-bot
sudo systemctl restart nginx

# Check status
echo "📊 Checking service status..."
sudo systemctl status security-bot --no-pager
sudo systemctl status nginx --no-pager

echo "✅ Deployment complete!"
echo "🌐 Your bot is now running on: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "📝 Don't forget to:"
echo "   1. Update your Slack app's Event Subscriptions URL"
echo "   2. Configure your .env file with proper credentials"
echo "   3. Test the bot in Slack!" 