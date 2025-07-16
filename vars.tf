# Authored by Antoine CICHOWICZ | Github: Yris Ops
# Copyright: Apache License 2.0

variable "aws_region" {
  description = "The AWS region in which resources will be deployed."
  type        = string
  default     = "ap-northeast-2"
}

variable "environment" {
  description = "The name of the environment (e.g., development, production)."
  type        = string
  default     = "development"
}

variable "vpc_cidr" {
  description = "The CIDR block for the Virtual Private Cloud (VPC)."
  type        = string
  default     = "172.16.0.0/16"
}

variable "public_subnets_cidr" {
  description = "CIDR blocks for the public subnets within the VPC."
  type        = list(string)
  default     = ["172.16.1.0/24", "172.16.2.0/24"]
}

variable "private_subnets_cidr" {
  description = "CIDR blocks for the private subnets within the VPC."
  type        = list(string)
  default     = ["172.16.3.0/24", "172.16.4.0/24"]
}

variable "GitHubToken" {
  description = "GitHub Token for accessing the repository."
  type        = string
  sensitive   = true
}

variable "GitHubRepo" {
  description = "The name of the GitHub repository."
  type        = string
  default     = "ga-project"
}

variable "GitHubOwner" {
  description = "The owner/organization of the GitHub repository."
  type        = string
  default     = "jangjangjin"
}

variable "GitHubBranch" {
  description = "The branch of the GitHub repository to use."
  type        = string
  default     = "main"
}

variable "BucketName" {
  description = "The name of the S3 bucket for storing artifacts."
  type        = string
  default     = "garangbi-terraform"
}

variable "NotificationEmail" {
  description = "The email address to receive deployment notifications."
  type        = string
}

variable "codebuild_project_name" {
  description = "The name of the CodeBuild project for building code."
  type        = string
  default     = "CodeBuildProject"
}

variable "aws_account_id" {
  description = "The AWS Account ID associated with the resources."
  type        = string
}