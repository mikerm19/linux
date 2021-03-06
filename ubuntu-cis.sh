#!/bin/bash
#CIS Ubuntu Benchmark
#mmason 3/27/2017

#Pre-Login Banner
banner="This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel. In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored. Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials."

apt-get install iptables-persistent etckeeper -y
apt-get remove telnet -y
etckeeper init

cat >>/etc/modprobe.d/cis.conf <<EOL
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install tipc /bin/true
EOL

chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

echo "$banner" > /etc/issue
echo "$banner" > /etc/issue.net
sed -i '/'Banner'/s/^#//g' /etc/ssh/sshd_config

echo '* hard core 0' >> /etc/security/limits.conf

cat >>/etc/sysctl.conf <<EOL
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
EOL

# Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
# Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
netfilter-persistent save

chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

sed -i '/'X11Forwarding'/s/^/#/g' /etc/ssh/sshd_config
sed -i '/'LoginGraceTime'/s/^/#/g' /etc/ssh/sshd_config

cat >>/etc/ssh/sshd_config <<EOL

X11Forwarding no
MaxAuthTries 4
PermitUserEnvironment no
ClientAliveCountMax 5
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
LoginGraceTime 60
EOL

sed -i '/'minlen'/s/^/#/g' /etc/security/pwquality.conf
cat >>/etc/security/pwquality.conf <<EOL
minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOL

echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
sed -i '/pam_unix.so/s/$/ remember=4/' /etc/pam.d/common-password

sed -i '/'PASS_MAX_DAYS'/s/^/#/g' /etc/login.defs
sed -i '/'PASS_MIN_DAYS'/s/^/#/g' /etc/login.defs
sed -i '/'PASS_WARN_AGE'/s/^/#/g' /etc/login.defs
cat >>/etc/login.defs <<EOL
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 7
EOL

echo 'umask 027' >> /etc/bash.bashrc
echo 'umask 027' >> /etc/profile

echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su

userdel -r games
userdel -r irc

echo 'Generate a random, secure password for the root user. Do not reuse passwords, and do not forget to put it in a password manager/document it! If a password is lost, the account can be reset with Azure CLI commands.'
passwd root
echo 'Aide init will now run. It will take a very long time.'
aideinit
systemctl enable auditd
etckeeper commit