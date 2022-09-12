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
  yum install -y unzip nginx jq sshpass wget policycoreutils-python-utils 
#  yum -y groupinstall "Development Tools"
  yum -y install selinux-policy-devel
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
mkdir -pm 0755 /etc/vault.d
mkdir -pm 0755 /opt/vault/setup
chown -R vault:vault /opt/vault
chown -R vault:vault /etc/vault.d
touch /opt/vault/setup/vault.unseal.info /opt/vault/setup/bootstrap_config.log

cat << EOF > /lib/systemd/system/vault.service
[Unit]
Description=Vault Agent
Requires=network-online.target
After=network-online.target
[Service]
Restart=on-failure
PermissionsStartOnly=true
ExecStartPre=/sbin/setcap 'cap_ipc_lock=+ep' /usr/local/bin/vault
ExecStart=/usr/local/bin/vault server -config /etc/vault.d
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
User=vault
Group=vault
[Install]
WantedBy=multi-user.target
EOF


cat << EOF > /etc/vault.d/vault.hcl
storage "file" {
  path = "/opt/vault/data"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
seal "awskms" {
  region     = "${aws_region}"
  kms_key_id = "${kms_key}"
}
ui=true
EOF

cat << EOF > /opt/vault/vault_create.sql
CREATE TABLE vault_kv_store (
  parent_path TEXT COLLATE "C" NOT NULL,
  path        TEXT COLLATE "C",
  key         TEXT COLLATE "C",
  value       BYTEA,
  CONSTRAINT pkey PRIMARY KEY (path, key)
);
CREATE INDEX parent_path_idx ON vault_kv_store (parent_path);
EOF

chmod 0664 /lib/systemd/system/vault.service
systemctl daemon-reload
chown -R vault:vault /etc/vault.d
chmod -R 0644 /etc/vault.d/*

cat << EOF > /etc/profile.d/vault.sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
EOF

source /etc/profile.d/vault.sh
echo "source /etc/profile.d/vault.sh" >> ~ec2-user/.bashrc

systemctl enable vault
systemctl start vault
sleep 12

vault operator init -recovery-shares=1 -recovery-threshold=1 >> /opt/vault/setup/vault.unseal.info
ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
vault login $ROOT_TOKEN >> /opt/vault/setup/bootstrap_config.log

vault login $ROOT_TOKEN

##
## finish off
##
echo "All Done"  >> /opt/vault/setup/bootstrap_config.log

##
## setup ssh otp
##
vault login $ROOT_TOKEN
vault secrets enable -path=ssh ssh
vault write ssh/roles/otp_key_role key_type=otp default_user=stoffee cidr_list=0.0.0.0/0
# Logout and Login using vault OTP one time so that it's in the audit_log
vault write ssh/creds/otp_key_role ip=8.8.8.8
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
make -f /usr/share/selinux/devel/Makefile /opt/vault/setup/vault-otp.pp
semodule -i /opt/vault/setup/vault-otp.pp

hostnamectl set-hostname vault
shutdown -r now