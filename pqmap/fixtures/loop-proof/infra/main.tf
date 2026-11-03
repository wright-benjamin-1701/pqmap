# AWS ALB in front of a Python app. The ALB terminates TLS (plan 05).
resource "aws_alb" "api" {
  name               = "payments-api"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sgid.id]
  subnets            = data.aws_subnets.public.ids

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sgid" {
  name = "payments-sg"
}

data "aws_subnets" "public" {
  filter {
    name   = "map:public"
    values = ["true"]
  }
}
