terraform {
  required_version = "1.2.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0, < 5.0.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}


resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
  force_destroy = true

  tags = {
    Name = "My bucket"
  }
}

resource "aws_s3_bucket_acl" "b_acl" {
  bucket = aws_s3_bucket.b.id
  acl    = "private"
}

locals {
  s3_origin_id = "myS3Origin"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  is_ipv6_enabled     = false
  comment             = "Some comment"
  default_root_object = "index.html"

  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  aliases = ["dev.bdbtest.com"] ##si me entregan un dominio cambio aca tambien

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE", "CO"]
    }
  }

  tags = {
    Environment = "develop"
  }

  web_acl_id = aws_waf_web_acl.waf_acl.id  

  viewer_certificate {
    cloudfront_default_certificate = false
    acm_certificate_arn = aws_acm_certificate.cert.arn 
    ssl_support_method = "sni-only"
    minimum_protocol_version = "TLSv1.2_2019"
  }
}

###############################lambda Edge##################################

resource "aws_iam_role" "lambda_edge_role" {
  name = "lambda_edge_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "lambda.amazonaws.com",
          "edgelambda.amazonaws.com",
          "cloudwatch.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "lambda_edge_index" {
  description      = "Basic HTTP authentication module/function"
  role             = aws_iam_role.lambda_edge_role.arn
  runtime          = "nodejs14.x"
  filename         = "lambda.zip"
  source_code_hash = filebase64sha256("lambda.zip")
  function_name    = "security-headers"
  handler          = "index.handler"
  timeout          = 1
  memory_size      = 128
  publish          = true

  lifecycle {
      ignore_changes = [
          handler,
          source_code_hash,
          runtime,
          filename
      ]
  }
}

#################################Hosted Zone Route 53##############################

resource "aws_route53_zone" "dev" {
  name = "dev.bdbtest.com" ## Si tengo dominio de prueba, cambio aca por el dominio que me den
  tags = {
    Environment = "dev"
  }
}

resource "aws_route53_record" "frontend_validation_record_dev" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.dev.id
}

###################### Certificate Manager ####################################
resource "aws_acm_certificate" "cert" {
  domain_name       = aws_route53_zone.dev.name
  validation_method = "DNS"

  tags = {
    Environment = "test"
  }

  lifecycle {
    create_before_destroy = true
  }
}



resource "aws_acm_certificate_validation" "frontend_validation_dev" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.frontend_validation_record_dev : record.fqdn]
}

##################################### WAF ###################################################3

resource "aws_waf_ipset" "ipset" {
  name = "tfIPSet"

  ip_set_descriptors {
    type  = "IPV4"
    value = "192.0.7.0/24"
  }
}

resource "aws_waf_rule" "wafrule" {
  depends_on  = [aws_waf_ipset.ipset]
  name        = "tfWAFRule"
  metric_name = "tfWAFRule"

  predicates {
    data_id = aws_waf_ipset.ipset.id
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_waf_web_acl" "waf_acl" {
  depends_on = [
    aws_waf_ipset.ipset,
    aws_waf_rule.wafrule,
  ]
  name        = "tfWebACL"
  metric_name = "tfWebACL"

  default_action {
    type = "ALLOW"
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 1
    rule_id  = aws_waf_rule.wafrule.id
    type     = "REGULAR"
  }
}

############################################### Second Part #####################################################
########################################ECS######################################################
resource "aws_ecs_cluster" "bdb-cluster" {
  name = "bdb-cluster"
}

resource "aws_ecs_task_definition" "bdb_task_definition" {
  family                   = "bdb-task-definition"
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "1024"
  requires_compatibilities = [ "FARGATE" ]
  container_definitions = jsonencode([
    {
      name      = "first"
      image     = "nginx:latest"
      cpu       = 10
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
    }
  ])
  lifecycle {
    ignore_changes = all
  }
}

resource "aws_ecs_service" "nginx" {
  name                               = "nginx"
  task_definition                    = aws_ecs_task_definition.bdb_task_definition.arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  cluster                            = aws_ecs_cluster.bdb-cluster.id
  platform_version                   = "LATEST"
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  scheduling_strategy                = "REPLICA"
  network_configuration {
    assign_public_ip = true
    security_groups  = [aws_security_group.appsg.id]
    subnets          = [data.aws_subnet.subnets.id, data.aws_subnet.subnets2.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.bdb_ecs_target.arn 
    container_name   = "first"
    container_port   = 80
  }
  lifecycle {
    ignore_changes = [
      task_definition,
      desired_count
    ]
  }
}

################################################IAM############################################

resource "aws_iam_role" "ecs_task_execution_role" {
    name = "bdb-task-execution-role"
    assume_role_policy = jsonencode({
    "Version":"2012-10-17",
    "Statement":[
        {
            "Action":"sts:AssumeRole",
            "Principal":{
                "Service":"ecs-tasks.amazonaws.com"
            },
            "Effect":"Allow",
            "Sid":""
        }
    ]
    })
}

resource "aws_iam_role" "ecs_task_role" {
    name = "bdb-task-role"
    assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
    {
        "Action": "sts:AssumeRole",
        "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
    }
 ]})
}

resource "aws_iam_role_policy_attachment" "ecs_ter_policy_attachment" {
    role       = aws_iam_role.ecs_task_execution_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "task_s3" {
    role       = aws_iam_role.ecs_task_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}


###################################Data Sources################################################

data "aws_vpc" "default" {
  filter {
    name = "tag:Name"
    values = ["default"]
    
  }
}

data "aws_subnet" "subnets" {
  filter {
    name = "tag:Name"
    values = ["private1"]
  }
}

data "aws_subnet" "subnets2" {
  filter {
    name = "tag:Name"
    values = ["private2"]
  }
}

# data "aws_subnet_ids" "subnets" {
#  vpc_id = data.aws_vpc.default.id
#  filter {
#     name = "tag:Name"
#     values = ["private*"]
#  }
# }

########################################Security Group###########################################

resource "aws_security_group" "appsg" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [data.aws_vpc.default.cidr_block]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

############################################## NLB #################################################

resource "aws_lb" "test" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "network"
  subnets            = [data.aws_subnet.subnets.id, data.aws_subnet.subnets2.id]

  enable_deletion_protection = false

  tags = {
    Environment = "production"
  }
}

resource "aws_lb_target_group" "bdb_ecs_target" {
  name        = "bbd-ecs-target"
  port        = 80  
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_lb_listener" "bdb_alb_listener" {
  load_balancer_arn = aws_lb.test.arn
  port = 80
  
  protocol = "TCP"
  default_action {
    target_group_arn = aws_lb_target_group.bdb_ecs_target.arn
    type = "forward"

  }
}

###########################################API Gateway###############################
resource "aws_api_gateway_rest_api" "example" {
  body = jsonencode({
    openapi = "3.0.1"
    info = {
      title   = "example"
      version = "1.0"
    }
    paths = {
      "/path1" = {
        ##faltan las demás rutas 
        get = {
          x-amazon-apigateway-integration = {
            httpMethod           = "GET"
            payloadFormatVersion = "1.0"
            type                 = "HTTP_PROXY"
            uri                  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
          }
        }
      }
    }
  })

  name = "example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.example.body))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}

##El api no está conectado ni al back ni al front por que no tengo la definición de la api (open api)
##