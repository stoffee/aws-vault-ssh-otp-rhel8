output "vault_ssh" {
  value = "Connect to Vault via SSH ssh: -i private.key ec2-user@${aws_instance.vault[0].public_ip}"
}

output "rhel_ssh" {
  value = "Connect to RHEL ssh host via:  ssh -i private.key ec2-user@${aws_instance.vault[0].public_ip}"
}
output "vault_url" {
  value = "Vault web Interface http://${aws_instance.vault[0].public_ip}:8200/ui"
}

#output "connections" {
#  value = <<VAULT
#Connect to Vault via SSH   ssh -i private.key ec2-user@${aws_instance.vault[0].public_ip}
#Connect to SSH RHEL Host        ssh -i private.key ec2-user@${aws_instance.ssh[0].public_ip}
#Vault web interface  http://${aws_instance.vault[0].public_ip}:8200/ui
#VAULT
#}

output "ssh" {
  value = <<SSH
value = "ssh -i signed-cert.pub -i ~/.ssh/id_rsa ec2-user@${aws_instance.ssh[0].public_dns}"
SSH
}