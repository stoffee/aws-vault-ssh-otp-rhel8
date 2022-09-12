output "vault_ssh" {
  value = "Connect to Vault via SSH: ssh -i private.key ec2-user@${aws_instance.ssh[0].public_ip}"
}

output "rhel_ssh" {
  value = "Connect to RHEL ssh host via:  ssh -i private.key ec2-user@${aws_instance.vault[0].public_ip}"
}
output "vault_url" {
  value = "Vault web Interface http://${aws_instance.vault[0].public_dns}:8200/ui"
}

output "ssh" {
  value = <<SSH
value = "ssh -i signed-cert.pub -i ~/.ssh/id_rsa ec2-user@${aws_instance.ssh[0].public_dns} p
  #Login using vault OTP one time so that it's in the audit_log
  #grep sshd_t /var/log/audit/audit.log | audit2allow -m vault-helper > vault-helper.te
  #make -f /usr/share/selinux/devel/Makefile vault-helper.pp
  #semodule -i vault-helper.pp
  #semodule -l | grep vault
  #setenforce 1"
SSH
}