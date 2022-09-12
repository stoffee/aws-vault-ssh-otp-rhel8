output "connections" {
  value = <<VAULT
Connect to Vault via SSH   ssh -i private.key ubuntu@${aws_instance.vault[0].public_ip}
Connect to SSH RHEL Host        ssh -i private.key ubuntu@${aws_instance.ssh[0].public_ip}
Vault web interface  http://${aws_instance.vault[0].public_ip}:8200/ui
NGINX web interface  https://${aws_instance.vault[0].public_ip}
VAULT
}

output "ssh" {
  value = <<SSH
----
----
On the SSH host and the bastion host do one of these:
sudo curl -o /etc/ssh/trusted-user-ca-keys.pem http://${aws_instance.vault[0].public_ip}:8200/v1/ssh-client-signer/public_key  
or
sudo su -
VAULT_ADDR=http://${aws_instance.vault[0].public_ip}:8200 vault read -field=public_key ssh-client-signer/config/ca > /etc/ssh/trusted-user-ca-keys.pem
----
Update the sshd_config on both SSH and Bastion host:
# /etc/ssh/sshd_config
# ...
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
---
Restart sshd: sudo systemctl restart sshd
----
Do this on the vault server:
---
create a sshkey:
ssh-keygen -t rsa -C "ubuntu"
----
Ask Vault to sign the public key:
vault login
vault write ssh-client-signer/sign/my-role \
    public_key=@$HOME/.ssh/id_rsa.pub
----
Save the signed key to disk:
vault write -field=signed_key ssh-client-signer/sign/my-role \
    public_key=@$HOME/.ssh/id_rsa.pub > signed-cert.pub
----
Now ssh to the client host:
ssh -i signed-cert.pub -i ~/.ssh/id_rsa ubuntu@${aws_instance.ssh[0].public_ip}
----
now that we can connect to the host, we want to connnect through the bastion
----
Add this to vault server ~vault/.ssh/ssh_config
Host bastion
  Hostname ${aws_instance.vault[0].public_dns}
  IdentityFile ~/.ssh/id_rsa
  CertificateFile ~/.ssh/signed-cert.pub
  User ubuntu
Host ${aws_instance.ssh[0].public_dns}
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -F uname bastion nc %h %p
  User ubuntu
----
Now let's try to connect:
ssh -i signed-cert.pub -i ~/.ssh/id_rsa ubuntu@${aws_instance.ssh[0].public_dns}
SSH
}