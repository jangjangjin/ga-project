# Authored by Antoine CICHOWICZ | Github: Yris Ops
# Copyright: Apache License 2.0

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.13.1"
    }
        datadog = {
      source = "DataDog/datadog"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

provider "datadog" {
  api_key = "e629ec98d1ada3e0a29bfd0152b8f640"
  app_key = "f4173c1d7760e7a08169310f8550c802930fd285"
}

# data dog ---------------------------------------------
data "aws_iam_policy_document" "datadog_aws_integration_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::464622532012:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values = [
        "${datadog_integration_aws_account.datadog_integration.auth_config.aws_auth_config_role.external_id}"
      ]
    }
  }
}

data "aws_iam_policy_document" "datadog_aws_integration" {
  statement {
    actions = [
      "apigateway:GET",
      "aoss:BatchGetCollection",
      "aoss:ListCollections",
      "autoscaling:Describe*",
      "backup:List*",
      "bcm-data-exports:GetExport",
      "bcm-data-exports:ListExports",
      "bedrock:GetAgent",
      "bedrock:GetAgentAlias",
      "bedrock:GetFlow",
      "bedrock:GetFlowAlias",
      "bedrock:GetGuardrail",
      "bedrock:GetImportedModel",
      "bedrock:GetInferenceProfile",
      "bedrock:GetMarketplaceModelEndpoint",
      "bedrock:ListAgentAliases",
      "bedrock:ListAgents",
      "bedrock:ListFlowAliases",
      "bedrock:ListFlows",
      "bedrock:ListGuardrails",
      "bedrock:ListImportedModels",
      "bedrock:ListInferenceProfiles",
      "bedrock:ListMarketplaceModelEndpoints",
      "bedrock:ListPromptRouters",
      "bedrock:ListProvisionedModelThroughputs",
      "budgets:ViewBudget",
      "cassandra:Select",
      "cloudfront:GetDistributionConfig",
      "cloudfront:ListDistributions",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:LookupEvents",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "codeartifact:DescribeDomain",
      "codeartifact:DescribePackageGroup",
      "codeartifact:DescribeRepository",
      "codeartifact:ListDomains",
      "codeartifact:ListPackageGroups",
      "codeartifact:ListPackages",
      "codedeploy:BatchGet*",
      "codedeploy:List*",
      "codepipeline:ListWebhooks",
      "cur:DescribeReportDefinitions",
      "directconnect:Describe*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ec2:Describe*",
      "ec2:GetAllowedImagesSettings",
      "ec2:GetEbsDefaultKmsKeyId",
      "ec2:GetInstanceMetadataDefaults",
      "ec2:GetSerialConsoleAccessStatus",
      "ec2:GetSnapshotBlockPublicAccessState",
      "ec2:GetTransitGatewayPrefixListReferences",
      "ec2:SearchTransitGatewayRoutes",
      "ecs:Describe*",
      "ecs:List*",
      "elasticache:Describe*",
      "elasticache:List*",
      "elasticfilesystem:DescribeAccessPoints",
      "elasticfilesystem:DescribeFileSystems",
      "elasticfilesystem:DescribeTags",
      "elasticloadbalancing:Describe*",
      "elasticmapreduce:Describe*",
      "elasticmapreduce:List*",
      "emr-containers:ListManagedEndpoints",
      "emr-containers:ListSecurityConfigurations",
      "emr-containers:ListVirtualClusters",
      "es:DescribeElasticsearchDomains",
      "es:ListDomainNames",
      "es:ListTags",
      "events:CreateEventBus",
      "fsx:DescribeFileSystems",
      "fsx:ListTagsForResource",
      "glacier:GetVaultNotifications",
      "glue:ListRegistries",
      "grafana:DescribeWorkspace",
      "greengrass:GetComponent",
      "greengrass:GetConnectivityInfo",
      "greengrass:GetCoreDevice",
      "greengrass:GetDeployment",
      "health:DescribeAffectedEntities",
      "health:DescribeEventDetails",
      "health:DescribeEvents",
      "kinesis:Describe*",
      "kinesis:List*",
      "lambda:GetPolicy",
      "lambda:List*",
      "lightsail:GetInstancePortStates",
      "logs:DeleteSubscriptionFilter",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:DescribeSubscriptionFilters",
      "logs:FilterLogEvents",
      "logs:PutSubscriptionFilter",
      "logs:TestMetricFilter",
      "macie2:GetAllowList",
      "macie2:GetCustomDataIdentifier",
      "macie2:ListAllowLists",
      "macie2:ListCustomDataIdentifiers",
      "macie2:ListMembers",
      "macie2:GetMacieSession",
      "managedblockchain:GetAccessor",
      "managedblockchain:GetMember",
      "managedblockchain:GetNetwork",
      "managedblockchain:GetNode",
      "managedblockchain:GetProposal",
      "managedblockchain:ListAccessors",
      "managedblockchain:ListInvitations",
      "managedblockchain:ListMembers",
      "managedblockchain:ListNodes",
      "managedblockchain:ListProposals",
      "memorydb:DescribeAcls",
      "memorydb:DescribeMultiRegionClusters",
      "memorydb:DescribeParameterGroups",
      "memorydb:DescribeReservedNodes",
      "memorydb:DescribeSnapshots",
      "memorydb:DescribeSubnetGroups",
      "memorydb:DescribeUsers",
      "oam:ListAttachedLinks",
      "oam:ListSinks",
      "organizations:Describe*",
      "organizations:List*",
      "osis:GetPipeline",
      "osis:GetPipelineBlueprint",
      "osis:ListPipelineBlueprints",
      "osis:ListPipelines",
      "proton:GetComponent",
      "proton:GetDeployment",
      "proton:GetEnvironment",
      "proton:GetEnvironmentAccountConnection",
      "proton:GetEnvironmentTemplate",
      "proton:GetEnvironmentTemplateVersion",
      "proton:GetRepository",
      "proton:GetService",
      "proton:GetServiceInstance",
      "proton:GetServiceTemplate",
      "proton:GetServiceTemplateVersion",
      "proton:ListComponents",
      "proton:ListDeployments",
      "proton:ListEnvironmentAccountConnections",
      "proton:ListEnvironmentTemplateVersions",
      "proton:ListEnvironmentTemplates",
      "proton:ListEnvironments",
      "proton:ListRepositories",
      "proton:ListServiceInstances",
      "proton:ListServiceTemplateVersions",
      "proton:ListServiceTemplates",
      "proton:ListServices",
      "qldb:ListJournalKinesisStreamsForLedger",
      "rds:Describe*",
      "rds:List*",
      "redshift:DescribeClusters",
      "redshift:DescribeLoggingStatus",
      "redshift-serverless:ListEndpointAccess",
      "redshift-serverless:ListManagedWorkgroups",
      "redshift-serverless:ListNamespaces",
      "redshift-serverless:ListRecoveryPoints",
      "redshift-serverless:ListSnapshots",
      "route53:List*",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketNotification",
      "s3:GetBucketTagging",
      "s3:ListAccessGrants",
      "s3:ListAllMyBuckets",
      "s3:PutBucketNotification",
      "s3express:GetBucketPolicy",
      "s3express:GetEncryptionConfiguration",
      "s3express:ListAllMyDirectoryBuckets",
      "s3tables:GetTableBucketMaintenanceConfiguration",
      "s3tables:ListTableBuckets",
      "s3tables:ListTables",
      "savingsplans:DescribeSavingsPlanRates",
      "savingsplans:DescribeSavingsPlans",
      "secretsmanager:GetResourcePolicy",
      "ses:Get*",
      "ses:ListAddonInstances",
      "ses:ListAddonSubscriptions",
      "ses:ListAddressLists",
      "ses:ListArchives",
      "ses:ListContactLists",
      "ses:ListCustomVerificationEmailTemplates",
      "ses:ListMultiRegionEndpoints",
      "ses:ListIngressPoints",
      "ses:ListRelays",
      "ses:ListRuleSets",
      "ses:ListTemplates",
      "ses:ListTrafficPolicies",
      "sns:GetSubscriptionAttributes",
      "sns:List*",
      "sns:Publish",
      "sqs:ListQueues",
      "states:DescribeStateMachine",
      "states:ListStateMachines",
      "support:DescribeTrustedAdvisor*",
      "support:RefreshTrustedAdvisorCheck",
      "tag:GetResources",
      "tag:GetTagKeys",
      "tag:GetTagValues",
      "timestream:DescribeEndpoints",
      "timestream:ListTables",
      "waf-regional:GetRule",
      "waf-regional:GetRuleGroup",
      "waf-regional:ListRuleGroups",
      "waf-regional:ListRules",
      "waf:GetRule",
      "waf:GetRuleGroup",
      "waf:ListRuleGroups",
      "waf:ListRules",
      "wafv2:GetIPSet",
      "wafv2:GetLoggingConfiguration",
      "wafv2:GetRegexPatternSet",
      "wafv2:GetRuleGroup",
      "wafv2:ListLoggingConfigurations",
      "workmail:DescribeOrganization",
      "workmail:ListOrganizations",
      "xray:BatchGetTraces",
      "xray:GetTraceSummaries"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "datadog_aws_integration" {
  name   = "DatadogAWSIntegrationPolicy"
  policy = data.aws_iam_policy_document.datadog_aws_integration.json
}
resource "aws_iam_role" "datadog_aws_integration" {
  name               = "DatadogIntegrationRole"
  description        = "Role for Datadog AWS Integration"
  assume_role_policy = data.aws_iam_policy_document.datadog_aws_integration_assume_role.json
}
resource "aws_iam_role_policy_attachment" "datadog_aws_integration" {
  role       = aws_iam_role.datadog_aws_integration.name
  policy_arn = aws_iam_policy.datadog_aws_integration.arn
}
resource "aws_iam_role_policy_attachment" "datadog_aws_integration_security_audit" {
  role       = aws_iam_role.datadog_aws_integration.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "datadog_integration_aws_account" "datadog_integration" {
  account_tags   = []
  aws_account_id = "934484537646"
  aws_partition  = "aws"
  aws_regions {
    include_all = true
  }
  auth_config {
    aws_auth_config_role {
      role_name = "DatadogIntegrationRole"
    }
  }
    resources_config {
    cloud_security_posture_management_collection = true
    extended_collection                          = true
  }
  traces_config {
    xray_services {
    }
  }
    logs_config {
    lambda_forwarder {
    }
  }
  metrics_config {
    namespace_filters {
    }
  }
}

locals {
  availability_zones = ["${var.aws_region}a", "${var.aws_region}b"]
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.public_subnets_cidr)
  cidr_block              = element(var.public_subnets_cidr, count.index)
  availability_zone       = element(local.availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-${element(local.availability_zones, count.index)}-public-subnet"
    Environment = "${var.environment}"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.private_subnets_cidr)
  cidr_block              = element(var.private_subnets_cidr, count.index)
  availability_zone       = element(local.availability_zones, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.environment}-${element(local.availability_zones, count.index)}-private-subnet"
    Environment = "${var.environment}"
  }
}

resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    "Name"        = "${var.environment}-igw"
    "Environment" = var.environment
  }
}

resource "aws_eip" "nat_eip" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.ig]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = element(aws_subnet.public_subnet.*.id, 0)

  tags = {
    Name        = "nat-gateway-${var.environment}"
    Environment = "${var.environment}"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name        = "${var.environment}-private-route-table"
    Environment = "${var.environment}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name        = "${var.environment}-public-route-table"
    Environment = "${var.environment}"
  }
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}

resource "aws_route" "private_internet_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.nat.id
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets_cidr)
  subnet_id      = element(aws_subnet.public_subnet.*.id, count.index)
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets_cidr)
  subnet_id      = element(aws_subnet.private_subnet.*.id, count.index)
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "app_sg" {
  name        = "app-security-group-alb"
  description = "Security group for the Flask app"
  vpc_id      = aws_vpc.vpc.id


  ingress {
    description = "Allow all traffic through port 80"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = "0"
    to_port     = "0"
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "app_alb" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app_sg.id]
  subnets            = aws_subnet.public_subnet[*].id

  enable_deletion_protection = false

  enable_http2 = true

  enable_cross_zone_load_balancing = true
}

resource "aws_lb_target_group" "app_target_group" {
  name        = "app-target-group"
  target_type = "ip"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id

  health_check {
    enabled             = true
    interval            = 300
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.app_target_group.arn
    type             = "forward"
  }
}

resource "aws_ecs_cluster" "app_cluster" {
  name = "app-cluster"
}

resource "aws_ecs_task_definition" "app_task" {
  family                   = "app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name  = "app-container",
      image = "${aws_ecr_repository.ecr_repo.repository_url}",
      portMappings = [
        {
          containerPort = 80,
          hostPort      = 80,
        },
      ],
    },
  ])
}

data "aws_iam_policy" "aws_ecs_task_execution_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_policy" "policy" {
  name = "ecs-Policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Action" : [
          "ecs:ListClusters",
          "ecs:ListTaskDefinitions",
          "ecs:ListContainerInstances",
          "ecs:RunTask",
          "ecs:StopTask",
          "ecs:DescribeTasks",
          "ecs:DescribeContainerInstances",
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
          "ecs:DeregisterTaskDefinition",
          "iam:GetRole",
          "iam:PassRole"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ecs-tasks.amazonaws.com",
        },
      },
    ],
  })

  managed_policy_arns = [
    data.aws_iam_policy.aws_ecs_task_execution_policy.arn,
    aws_iam_policy.policy.arn
  ]
}

resource "aws_ecs_service" "app_service" {
  name            = "app-service"
  cluster         = aws_ecs_cluster.app_cluster.id
  task_definition = aws_ecs_task_definition.app_task.arn
  launch_type     = "FARGATE"
  desired_count   = 2

  network_configuration {
    subnets = aws_subnet.private_subnet[*].id

    security_groups = [aws_security_group.app_sg.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_target_group.arn
    container_name   = "app-container"
    container_port   = 80
  }

  depends_on = [aws_lb_listener.app_listener]
}

resource "aws_ecr_repository" "ecr_repo" {
  name = "ecs-flaskapp"

   force_delete = true
}

locals {
  repo_endpoint = split("/", aws_ecr_repository.ecr_repo.repository_url)[0]
}

resource "null_resource" "build_and_push_image" {
  provisioner "local-exec" {
    command = <<EOT
  echo "--- Build image ---"
  aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${local.repo_endpoint}
  docker build -t ecs-flaskapp . --platform linux/amd64
  docker tag ecs-flaskapp:latest ${aws_ecr_repository.ecr_repo.repository_url}:latest
  docker push ${aws_ecr_repository.ecr_repo.repository_url}:latest
EOT
  }
}


resource "aws_s3_bucket" "bucket_arti" {
  bucket        = var.BucketName
  force_destroy = true
}


resource "aws_iam_role" "CodePipelineRole" {
  name = "CodePipelineRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["codepipeline.amazonaws.com", "codebuild.amazonaws.com"]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "CodeBuildRole" {
  name = "CodeBuildRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["codebuild.amazonaws.com"]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

}

resource "aws_iam_policy" "CodePipelinePolicy" {
  name        = "CodePipelinePolicy"
  description = "IAM policy for S3, Cloudwatch Logs, SNS, ECR,  permissions for CodePipeline"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["ecr:GetAuthorizationToken", "ecs:UpdateService", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["sns:Publish"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["s3:*"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["codebuild:*"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["codestar-connections:UseConnection"],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
    }
  )
}


resource "aws_iam_policy" "CodeBuildPolicy" {
  name        = "CodeBuildPolicy"
  description = "IAM policy for S3, Cloudwatch Logs, SNS, ECR,  permissions for CodeBuild"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["ecr:GetAuthorizationToken", "ecs:UpdateService", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["sns:Publish"],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action   = ["s3:*"],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
    }
  )
}

resource "aws_iam_policy_attachment" "CodePipelinedAttachment" {
  name       = "CodePipelineAttachment"
  policy_arn = aws_iam_policy.CodePipelinePolicy.arn
  roles      = [aws_iam_role.CodePipelineRole.name]
}

resource "aws_iam_policy_attachment" "CodeBuildAttachment" {
  name       = "CodeBuildAttachment"
  policy_arn = aws_iam_policy.CodeBuildPolicy.arn
  roles      = [aws_iam_role.CodeBuildRole.name]
}

resource "aws_codebuild_project" "CodeBuildProject" {
  name         = "CodeBuildProject"
  service_role = aws_iam_role.CodeBuildRole.arn

  source {
    type                = "GITHUB"
    location            = "https://github.com/${var.GitHubOwner}/${var.GitHubRepo}.git"
    buildspec           = "buildspec.yml"
    report_build_status = false
  }


  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type            = "LINUX_CONTAINER"
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    privileged_mode = true
  }

}

resource "aws_codepipeline_webhook" "GithubWebhook" {
  name            = "test-webhook-github"
  authentication  = "GITHUB_HMAC"

  authentication_configuration {
    secret_token = var.GitHubToken
  }

  filter {
    json_path    = "$.ref"
    match_equals = "refs/heads/main"  # 실제 브랜치 이름
  }

  target_pipeline = aws_codepipeline.CodePipeline.name
  target_action   = "Source"
}



resource "aws_codepipeline" "CodePipeline" {
  name     = "ECS-Pipeline"
  role_arn = aws_iam_role.CodePipelineRole.arn

  artifact_store {
    type     = "S3"
    location = aws_s3_bucket.bucket_arti.bucket
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["SourceCode"]

      configuration = {
        ConnectionArn    = aws_codestarconnections_connection.github.arn
        FullRepositoryId = "${var.GitHubOwner}/${var.GitHubRepo}"
        BranchName       = var.GitHubBranch
        DetectChanges    = "true"
      }
      run_order = 1
    }
  }

  stage {
    name = "Build"

    action {
      name = "BuildAction"

      category        = "Build"
      owner           = "AWS"
      version         = "1"
      provider        = "CodeBuild"
      input_artifacts = ["SourceCode"]

      configuration = {
        ProjectName = aws_codebuild_project.CodeBuildProject.name
      }

      output_artifacts = ["BuildOutput"]
      run_order        = 2
    }
  }

}


resource "aws_sns_topic" "SnsTopicCodeBuild" {
  name = "SnsTopicCodeBuild"
}

resource "aws_iam_role" "SampleNotificationRuleRole" {
  name = "SampleNotificationRuleRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_sns_topic_policy" "SnsTopicPolicy" {
  arn = aws_sns_topic.SnsTopicCodeBuild.arn

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sns:Publish",
        Effect = "Allow",
        Principal = {
          Service = "events.amazonaws.com"
        },
        Resource = aws_sns_topic.SnsTopicCodeBuild.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "EventBridgeRule" {
  name          = "codebuild-notif"
  event_pattern = <<PATTERN
{
    "source": ["aws.codebuild"],
    "detail-type": ["CodeBuild Build State Change"],
    "detail": {
        "build-status": [
            "IN_PROGRESS",
            "SUCCEEDED", 
            "FAILED",
            "STOPPED"
        ]
    }
}
PATTERN

}



resource "aws_sns_topic_subscription" "SnsTopicSubscription" {
  topic_arn = aws_sns_topic.SnsTopicCodeBuild.arn
  protocol  = "email"
  endpoint  = var.NotificationEmail
}

resource "aws_codestarconnections_connection" "github" {
  name          = "github-connection"
  provider_type = "GitHub"
}


# 1. Virtual Private Gateway 생성
resource "aws_vpn_gateway" "main" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.environment}-vpn-gw"
  }
}

# 2. Customer Gateway 생성 (온프레미스 정보 입력)
resource "aws_customer_gateway" "main" {
  bgp_asn    = 65000  # 온프레미스 장비의 BGP ASN (정적 라우팅이면 아무 값이나 가능)
  ip_address = "121.160.41.53"  
  type       = "ipsec.1"
  tags = {
    Name = "${var.environment}-customer-gw"
  }
}

# 3. Site-to-Site VPN 연결 생성
resource "aws_vpn_connection" "main" {
  vpn_gateway_id      = aws_vpn_gateway.main.id
  customer_gateway_id = aws_customer_gateway.main.id
  type                = "ipsec.1"

  static_routes_only = true  # 정적 라우팅 사용 시 true

  tags = {
    Name = "${var.environment}-vpn-connection"
  }
}

# 4. VPN Connection Route (온프레미스 네트워크 대역)
resource "aws_vpn_connection_route" "onprem" {
  vpn_connection_id = aws_vpn_connection.main.id
  destination_cidr_block = "172.18.0.0/16"  # 온프레미스 네트워크 대역
}

# 5. VPC Route Table에 온프레미스 경로 추가
resource "aws_route" "to_onprem" {
  route_table_id         = aws_route_table.private.id  # 또는 public.id, 필요에 따라
  destination_cidr_block = "172.18.0.0/24"
  gateway_id             = aws_vpn_gateway.main.id
}
# =====================================






# ==============lmabda =====================
resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_lambda_function" "format_notification" {
  function_name = "FormatCodeBuildNotification"
  handler       = "string_format.lambda_handler"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_exec_role.arn
  filename      = "string_format.zip"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.SnsTopicCodeBuild.arn
    }
  }
}


resource "aws_cloudwatch_event_target" "LambdaTarget" {
  rule      = aws_cloudwatch_event_rule.EventBridgeRule.name
  target_id = "FormattedCodeBuild"
  arn       = aws_lambda_function.format_notification.arn
}

resource "aws_lambda_permission" "AllowCWInvoke" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.format_notification.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.EventBridgeRule.arn
}


resource "aws_iam_policy" "lambda_sns_publish" {
  name = "lambda-sns-publish"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "sns:Publish",
        Resource = aws_sns_topic.SnsTopicCodeBuild.arn
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "lambda_sns_publish_attach" {
  name       = "lambda-sns-publish-attach"
  policy_arn = aws_iam_policy.lambda_sns_publish.arn
  roles      = [aws_iam_role.lambda_exec_role.name]
}


# ----- cdn  --------
module "cloudfront" {
  source  = "terraform-aws-modules/cloudfront/aws"
  version = "~> 3.0"

  aliases = ["garangbi.xyz"]

  enabled             = true
  comment             = "garangbi.xyz CDN"
  default_root_object = "index.html"

  origin = {
    alb = {
      domain_name = aws_lb.app_alb.dns_name
      origin_id   = "alb-origin"
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "http-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior = {
    target_origin_id       = "alb-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
  }

  viewer_certificate = {
    acm_certificate_arn     = "arn:aws:acm:us-east-1:934484537646:certificate/9f37c0d2-d806-4c4a-b7f4-0a4738e8f2c6"
    ssl_support_method      = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  price_class = "PriceClass_200"
}