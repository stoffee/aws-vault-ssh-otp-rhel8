terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.30.0"
    }
  }
}

provider "aws" {
  region     = var.aws_region
}

resource "random_pet" "env" {
  length    = 2
  separator = "-"
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true

  tags = {
    Name  = "${var.namespace}-${random_pet.env.id}"
    Owner = var.owner
    TTL   = "96"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.namespace}-${random_pet.env.id}"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.vpc_cidr
  availability_zone       = var.aws_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.namespace}-pub-${random_pet.env.id}"
  }
}

resource "aws_route_table" "route" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${var.namespace}-${random_pet.env.id}"
  }
}

resource "aws_route_table_association" "route" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.route.id
}

resource "aws_kms_key" "vault" {
  description             = "Vault unseal key"
  deletion_window_in_days = 10

  tags = {
    Name = "${var.namespace}-${random_pet.env.id}"
  }
}

data "aws_ami" "rhel_8_5" {
  most_recent = "true"
  owners      = ["309956199498"]

  filter {
    name   = "name"
    values = ["RHEL-8.5*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "vault" {
  ami           = data.aws_ami.ubuntu.id
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
    Name = "${var.namespace}-${random_pet.env.id}"
  }

  user_data = data.template_file.vault.rendered
}

data "template_file" "vault" {
  template = file("vault.tpl")

  vars = {
    kms_key    = aws_kms_key.vault.id
    vault_url  = var.vault_url
    aws_region = var.aws_region
  }
}

data "template_file" "format_ssh" {
  template = "connect to host with following command: ssh ubuntu@$${admin} -i private.key"

  vars = {
    admin = aws_instance.vault[0].public_ip
  }
}



resource "aws_security_group" "vault" {
  name        = "${var.namespace}-${random_pet.env.id}"
  description = "vault access"
  vpc_id      = aws_vpc.vpc.id

  tags = {
    Name = "${var.namespace}-${random_pet.env.id}"
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # NGINX
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # POSTGRES
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Vault Client Traffic
  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "vault-kms-unseal" {
  statement {
    sid       = "VaultKMSUnseal"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
  }
}

resource "aws_iam_role" "vault-kms-unseal" {
  name               = "${var.namespace}-role-${random_pet.env.id}"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy" "vault-kms-unseal" {
  name   = "${var.namespace}-${random_pet.env.id}"
  role   = aws_iam_role.vault-kms-unseal.id
  policy = data.aws_iam_policy_document.vault-kms-unseal.json
}

resource "aws_iam_instance_profile" "vault-kms-unseal" {
  name = "${var.namespace}-${random_pet.env.id}"
  role = aws_iam_role.vault-kms-unseal.name
}