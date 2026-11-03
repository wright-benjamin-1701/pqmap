resource "aws_alb" "main" {
  name               = "payment-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnets

  security_groups = [aws_security_group.alb.id]
}

resource "aws_alb_listener" "https" {
  load_balancer_arn = aws_alb.main.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.cert_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.app.arn
  }
}

resource "aws_alb_target_group" "app" {
  name     = "payment-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}
