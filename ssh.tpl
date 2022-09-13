#!/usr/bin/env bash

USER="vault"
COMMENT="Hashicorp Vault user"
GROUP="vault"
HOME="/opt/vault"

# Detect package management system.
YUM=$(which yum 2>/dev/null)
APT_GET=$(which apt-get 2>/dev/null)

user_rhel() {
  # RHEL user setup
  sudo /usr/sbin/groupadd --force --system $${GROUP}

  if ! getent passwd $${USER} >/dev/null ; then
    sudo /usr/sbin/adduser \
      --system \
      --gid $${GROUP} \
      --home $${HOME} \
      --no-create-home \
      --comment "$${COMMENT}" \
      --shell /bin/false \
      $${USER}  >/dev/null
  fi
}

user_ubuntu() {
  # UBUNTU user setup
  if ! getent group $${GROUP} >/dev/null
  then
    sudo addgroup --system $${GROUP} >/dev/null
  fi

  if ! getent passwd $${USER} >/dev/null
  then
    sudo adduser \
      --system \
      --disabled-login \
      --ingroup $${GROUP} \
      --home $${HOME} \
      --no-create-home \
      --gecos "$${COMMENT}" \
      --shell /bin/false \
      $${USER}  >/dev/null
  fi
}

if [[ ! -z $${YUM} ]]; then
  logger "Setting up user $${USER} for RHEL/CentOS"
  user_rhel
  yum install -y unzip nginx jq sshpass wget  policycoreutils-python-utils selinux-policy-devel 
 #   yum -y groupinstall "Development Tools"
    setenforce 0
elif [[ ! -z $${APT_GET} ]]; then
  logger "Setting up user $${USER} for Debian/Ubuntu"
  user_ubuntu
else
  logger "$${USER} user not created due to OS detection failure"
  exit 1;
fi

logger "User setup complete"



VAULT_ZIP="vault.zip"
VAULT_URL="${vault_url}"
curl --silent --output /tmp/$${VAULT_ZIP} $${VAULT_URL}
unzip -o /tmp/$${VAULT_ZIP} -d /usr/local/bin/
chmod 0755 /usr/local/bin/vault
chown vault:vault /usr/local/bin/vault
ln -s /usr/local/bin/vault /usr/bin/vault
mkdir -p /opt/vault/setup/

cat << EOF > /etc/profile.d/vault.sh
export VAULT_ADDR=http://${vault_address}:8200
export VAULT_SKIP_VERIFY=true
EOF

source /etc/profile.d/vault.sh
echo "source /etc/profile.d/vault.sh" >> ~ec2-user/.bashrc


wget https://releases.hashicorp.com/vault-ssh-helper/0.2.1/vault-ssh-helper_0.2.1_linux_amd64.zip
unzip -q vault-ssh-helper_0.2.1_linux_amd64.zip -d /usr/local/bin
chmod 0755 /usr/local/bin/vault-ssh-helper
chown root:root /usr/local/bin/vault-ssh-helper

mkdir -p /etc/vault-ssh-helper.d/
cat << POF > /etc/vault-ssh-helper.d/config.hcl
vault_addr = http://${vault_address}:8200"
tls_skip_verify = true
ssh_mount_point = "ssh"
allowed_roles = "*"
POF


cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/ChallengeResponseAuthentication no/#ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config
sed -i 's/UsePAM no/#UsePAM no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication no/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/#PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd

cp /etc/pam.d/sshd /etc/pam.d/sshd.orig
sed -i 's/auth       substack     password-auth/#auth       substack     password-auth/' /etc/pam.d/sshd 
sed -i -e "2i auth requisite pam_exec.so quiet expose_authtok log=/var/log/vault-ssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl" /etc/pam.d/sshd

sudo useradd -d /home/stoffee -m stoffee

cat << FOF > /opt/vault/setup/vault-otp.te
module vault-otp 1.0;

require {
    type var_log_t;
    type sshd_t;
    type http_port_t;
    class file open;
    class file create;
    class tcp_socket name_connect;
}

allow sshd_t var_log_t:file open;
allow sshd_t var_log_t:file create;
allow sshd_t http_port_t:tcp_socket name_connect;

# references:
# https://github.com/hashicorp/vault-ssh-helper/issues/31#issuecomment-335565489
# http://www.admin-magazine.com/Articles/Credential-management-with-HashiCorp-Vault/(offset)/3
FOF
cd /opt/vault/setup/
make -f /usr/share/selinux/devel/Makefile vault-otp.pp
semodule -i vault-otp.pp

hostnamectl set-hostname ssh
shutdown -r now