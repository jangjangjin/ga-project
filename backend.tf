terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "garangbi-tfstate-bucket"
    key          = "terraform.tfstate"
    region       = "ap-northeast-2"
    encrypt      = true
    use_lockfile = true 
  }
}
