output "rhel_ssh" {
  value = "Connect to RHEL SSH Client: ssh -i private.key ec2-user@${aws_instance.ssh[0].public_ip}"
}

output "vault_ssh" {
  value = "Connect to Vault host:  ssh -i private.key ec2-user@${aws_instance.vault[0].public_ip}"
}
output "vault_url" {
  value = "Vault web Interface http://${aws_instance.vault[0].public_dns}:8200/ui"
}

output "ssh" {
  value = <<SSH
value = "ssh -i signed-cert.pub -i ~/.ssh/id_rsa ec2-user@${aws_instance.ssh[0].public_dns} p
SSH
}