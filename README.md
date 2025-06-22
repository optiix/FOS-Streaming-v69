# FOS-Streaming v69 - Secure Edition

🎯 **Professional IPTV Streaming Platform with Enterprise Security**

## 🚀 Features

### Core Streaming
- **Streaming & Re-streaming** - Authentication, M3U8 playlists
- **Multi-format Support** - HLS, RTMP, HTTP streaming
- **Transcoding Profiles** - Predefined and custom profiles
- **Proxy Mode** - Efficient stream relay capabilities
- **Multi-stream Channels** - Multiple sources per channel

### User Management
- **Complete User Control** - Add, edit, delete, enable/disable users
- **Stream Limits** - Per-user concurrent stream limits
- **Authentication** - Secure login with rate limiting
- **User Activity Tracking** - Detailed usage analytics

### Content Management
- **Category Management** - Organize content efficiently
- **Stream Management** - Start, stop, configure streams
- **Playlist Import** - Bulk import capabilities
- **Last IP Tracking** - Monitor user connections

### Security Features 🔒
- **IP Blocking** - Automatic and manual IP blocking
- **User Agent Blocking** - Block malicious bots and scrapers
- **Rate Limiting** - Prevent abuse and DDoS attacks
- **Fail2Ban Integration** - Advanced intrusion prevention
- **Secure Authentication** - Protected against brute force
- **CSRF Protection** - Cross-site request forgery prevention

### Administration
- **Settings Management** - Complete system configuration
- **Auto-restart** - Automated service recovery
- **Health Monitoring** - System status and alerts
- **Backup System** - Automated data protection

## 🖥️ System Requirements

### Supported Platforms
- **Debian 12 (Bookworm)** - Full feature support
- **Raspberry Pi OS 64-bit** - Optimized for Pi 4B+/Pi 5
- **Ubuntu 22.04+** - Community tested

### Hardware Requirements
- **Minimum**: 2GB RAM, 2 CPU cores, 20GB storage
- **Recommended**: 4GB+ RAM, 4+ CPU cores, SSD storage
- **Raspberry Pi**: Pi 4B+ (4-8GB RAM) or Pi 5

### Software Dependencies
- **PHP 8.1+** with required extensions
- **MariaDB 10.11+** or MySQL 8.0+
- **Nginx** with RTMP module
- **FFmpeg** (latest static build)

## 📦 Installation

### Quick Installation

#### Debian 12 (Standard)
```bash
curl -s https://raw.githubusercontent.com/optiix/FOS-Streaming-v69/main/install/debian12 | sudo bash
```

#### Raspberry Pi OS (ARM64)
```bash
curl -s https://raw.githubusercontent.com/optiix/FOS-Streaming-v69/main/install/raspberry-pi | sudo bash
```

#### Legacy Debian 11 (PHP 7.3)
```bash
curl -s https://raw.githubusercontent.com/optiix/FOS-Streaming-v69/main/install/debian11 | sudo bash
```

### Post-Installation Setup

1. **Access Web Panel**
   ```
   http://your-server-ip:7777
   Default Login: admin / admin
   ```

2. **⚠️ SECURITY: Change Default Password**
   - Login immediately after installation
   - Change admin password to a strong password
   - Update all default settings

3. **Configure Server Settings**
   - Update "Web IP" in Settings with your public IP
   - Configure FFmpeg paths if needed
   - Set up SMTP for notifications (optional)

4. **Setup Automated Monitoring**
   ```bash
   # The installation script automatically creates systemd services
   # Verify they're running:
   systemctl status fos-streaming-monitor.timer
   ```

5. **View Database Credentials**
   ```bash
   # MySQL root password
   cat /root/.fos-streaming/mysql_root_password
   
   # FOS database password  
   cat /root/.fos-streaming/mysql_fos_password
   ```

## 🔧 Configuration

### Port Configuration
To change the web panel port:

1. **Update Settings**
   - Go to Settings → Web Port
   - Change to desired port

2. **Update Nginx Configuration**
   ```bash
   nano /home/fos-streaming/fos/nginx/conf/nginx.conf
   # Change: listen 7777; to your desired port
   ```

3. **Restart Services**
   ```bash
   killall nginx; killall nginx_fos
   /home/fos-streaming/fos/nginx/sbin/nginx_fos
   ```

### Security Configuration

#### Firewall (UFW)
The installation automatically configures UFW. To modify:
```bash
# Add custom port
ufw allow 8888/tcp

# Remove default web port if changed
ufw delete allow 7777/tcp
```

#### Fail2Ban
Check protection status:
```bash
fail2ban-client status
fail2ban-client status fos-streaming
```

## 📚 Usage Guide

### Getting Started
1. **Create Categories**
   - Navigate to Categories
   - Add content categories (Movies, Sports, etc.)

2. **Add Streams**
   - Go to Streams section
   - Add new stream with source URL
   - Select transcode profile (recommend: "Default 1")
   - Configure for your needs

3. **Create Users**
   - User Management section
   - Set connection limits
   - Assign categories
   - Generate playlists

### Best Practices
- **Stability**: Use "Default 1" transcode profile for best stability
- **Performance**: Disable proxy mode for better performance
- **Security**: Regularly update blocked IPs and user agents
- **Monitoring**: Check logs regularly in `/var/log/fos-streaming/`

### Playlist Access
Users can access playlists via:
```
http://your-server:7777/playlist.php?username=USER&password=PASS&m3u
```

## 📊 Monitoring & Maintenance

### Log Files
- **Application**: `/var/log/fos-streaming/app.log`
- **PHP Errors**: `/var/log/fos-streaming/php-error.log`
- **Nginx**: `/var/log/nginx/`
- **System**: `/var/log/syslog`

### Health Checks
```bash
# Check services
systemctl status php8.1-fpm nginx mariadb

# Check FOS processes
ps aux | grep nginx_fos

# Monitor resources
htop
iftop
```

### Backup & Recovery
Automated backups are stored in `/var/backups/fos-streaming/`

Manual backup:
```bash
# Database
mysqldump -u root -p fos > fos_backup_$(date +%Y%m%d).sql

# Configuration
tar -czf fos_config_backup.tar.gz /home/fos-streaming/fos/www/.env
```

## 🛡️ Security Features

### Automatic Protection
- **Brute Force Protection** - Failed login blocking
- **DDoS Mitigation** - Rate limiting and connection limits
- **Bot Protection** - User agent filtering
- **Geographic Filtering** - Country-based blocking
- **Secure Headers** - XSS, CSRF, and injection protection

### Manual Security
- **IP Whitelist/Blacklist** - Manual IP management
- **User Agent Rules** - Custom bot blocking
- **Access Control** - User-level permissions
- **Audit Logging** - Complete activity tracking

## 🔧 Troubleshooting

### Common Issues

#### Streams Not Playing
1. Check FFmpeg installation: `ffmpeg -version`
2. Verify source URL accessibility
3. Check transcode profile settings
4. Review nginx error logs

#### Web Panel Inaccessible
1. Verify nginx is running: `ps aux | grep nginx_fos`
2. Check firewall: `ufw status`
3. Confirm port configuration

#### High Resource Usage
1. Monitor with `htop` and `iftop`
2. Reduce concurrent streams
3. Optimize transcode settings
4. Consider hardware upgrade

### Getting Help
- **Logs**: Always check `/var/log/fos-streaming/` first
- **GitHub Issues**: Report bugs with log excerpts
- **Community**: Join discussions for tips and tricks

## 📄 License & Credits

### Sources & Attribution
1. **FOS-Streaming-v1** - Original foundation
2. **FFmpeg** - Media processing engine  
3. **Nginx + RTMP Module** - Web server and streaming
4. **Security Enhancements** - optiix/FOS-Streaming-v69

### License
This project builds upon open-source foundations. Please respect all upstream licenses and contributors.

---

## ⚠️ Important Security Notes

- **Change all default passwords immediately**
- **Keep system updated**: `apt update && apt upgrade`
- **Monitor logs regularly** for suspicious activity
- **Use strong passwords** for all accounts
- **Enable HTTPS** in production environments
- **Regular backups** are essential

---

**🎯 Ready to stream securely!** This enhanced version provides enterprise-grade security while maintaining the simplicity and performance of the original FOS-Streaming platform.
