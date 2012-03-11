## Debian 6 VPS Script

Remove excess packages and install the basic components needed for a light-weight HTTP(S) web server.

 - dropbear (SSH)
 - iptables (firewall)
 - dash (replaces bash)
 - syslogd
 - MySQL
 - PHP-FPM
 - nginx (+1.0 from dotdeb)
 - vim & nano

Includes sample nginx config files for PHP sites. You can create a basic site shell (complete with nginx vhost) like this:

./setup-debian.sh site example.com

When running the iptables install you must specify a SSH port to allow (22 is the default). Future support will allow xinetd.d to use an alternate port for SSH. However, for now port 22 is all that works with this script and xinetd.d.
