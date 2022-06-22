terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.74.0"
    }
  }
}



provider "aws" {
  # shared_config_files      = ["/root/.aws/config"]
  # shared_credentials_file = "/root/.aws/credentials"
  region = "us-east-1"
  # shared_credentials_file = "~/.aws/credentials"
  # access_key = var.access_key
  # secret_key = var.secret_key
}

resource "aws_security_group" "instance1606" {
  description = "security group for ec2"
  ingress = [
    {
      # ssh port allowed from any ip
      description      = "ssh"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    },
        {
      description      = "html"
      from_port        = 8080
      to_port          = 8080
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    },
    {
      description      = "zabix-agent"
      from_port        = 10050
      to_port          = 10060
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    }
  ]
  egress = [
    {
      description      = "all-open"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      security_groups  = null
      self             = null
    }
  ]
}

resource "aws_iam_policy" "ec2_policy" {
  name        = "ec2_policy"
  path        = "/"
  description = "Policy to provide permission to EC2"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
    {
      Effect = "Allow"
      Action =["s3:*"]
      Resource = ["*"]
    }
  ]
  })
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
    {
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com"}
      Action = "sts:AssumeRole"
    }
  ]
  })
}

resource "aws_iam_policy_attachment" "ec2_policy_role" {
  name       = "ec2_attachment"
  roles      = [aws_iam_role.ec2_role.name]
  policy_arn = aws_iam_policy.ec2_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_key_pair" "generated_key" {
  key_name   = "generated_key"
  public_key = "${file("~/.ssh/id_rsa.pub")}"
}

variable "ami_id" {
    description = "ami"
    type = string
    default = "ami-09d56f8956ab235b3"
}

variable "instance_type" {
    description = "instance_type"
    type = string
    default = "t2.micro"
}

resource "aws_instance" "terraforminstance" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  vpc_security_group_ids = [aws_security_group.instance1606.id]
  key_name                    = aws_key_pair.generated_key.key_name
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

 
  connection {
      type        = "ssh"
      host        = self.public_ip
      user        = "ubuntu"
      private_key = file("~/.ssh/id_rsa")
      # private_key = tls_private_key.example.private_key_pem
   }
}