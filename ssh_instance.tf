resource "aws_instance" "ssh" {
  depends_on = [ aws_instance.vault ]
  ami           = data.aws_ami.rhel_8_5.id
  instance_type = var.instance_type
  count         = 1
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = var.ssh_key_name

  security_groups = [
    aws_security_group.vault.id,
  ]

  associate_public_ip_address = true
  ebs_optimized               = false
  iam_instance_profile        = aws_iam_instance_profile.vault-kms-unseal.id

  tags = {
    Name = "${var.namespace}-${random_pet.env.id}-ssh"
  }

  user_data = data.template_file.ssh.rendered
}

data "template_file" "ssh" {
  template = file("ssh.tpl")

  vars = {
    vault_url  = var.vault_url
    aws_region = var.aws_region
    #vault_address = aws_instance.ssh[0].public_ip

  }
}

#data "template_file" "format_ssh" {
#  template = "connect to host with following command: ssh ubuntu@$${admin} -i private.key"
#
#  vars = {
#    admin = aws_instance.ssh[0].public_ip
#  }
#}