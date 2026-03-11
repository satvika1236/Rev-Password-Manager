variable "project_name" {
  description = "Base name for all Phase 1 AWS resources."
  type        = string
  default     = "password-manager"
}

variable "environment" {
  description = "Environment suffix used in resource names."
  type        = string
  default     = "phase1"
}

variable "aws_region" {
  description = "AWS region for the Phase 1 deployment."
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "Primary CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Two public subnet CIDR blocks for the ALB and NAT gateway."
  type        = list(string)
  default     = ["10.42.1.0/24", "10.42.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Two private subnet CIDR blocks for EC2 and RDS."
  type        = list(string)
  default     = ["10.42.11.0/24", "10.42.12.0/24"]
}

variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to reach the public ALB listener."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "app_domain_name" {
  description = "Optional DNS name for the deployed application."
  type        = string
  default     = ""
}

variable "frontend_allowed_origins" {
  description = "Explicit CORS origins for frontend traffic. Leave empty to derive from the ALB DNS name."
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Optional EC2 key pair name for break-glass SSH access."
  type        = string
  default     = ""
}

variable "frontend_container_port" {
  description = "Host port exposed by the frontend container."
  type        = number
  default     = 80
}

variable "backend_container_port" {
  description = "Host port exposed by the backend container."
  type        = number
  default     = 8080
}

variable "frontend_health_path" {
  description = "Frontend health check path."
  type        = string
  default     = "/healthz"
}

variable "backend_health_path" {
  description = "Backend readiness path."
  type        = string
  default     = "/actuator/health"
}

variable "db_name" {
  description = "Application database name."
  type        = string
  default     = "rev_password_manager"
}

variable "db_username" {
  description = "Master username for the MySQL instance."
  type        = string
  default     = "appuser"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "Initial RDS allocated storage in GB."
  type        = number
  default     = 20
}

variable "rds_engine_version" {
  description = "MySQL engine version for RDS."
  type        = string
  default     = "8.0.40"
}

variable "mail_host" {
  description = "SMTP host for the production profile."
  type        = string
  default     = "smtp.gmail.com"
}

variable "mail_port" {
  description = "SMTP port for the production profile."
  type        = number
  default     = 587
}

variable "mail_username" {
  description = "SMTP username stored in Secrets Manager."
  type        = string
  default     = ""
}

variable "mail_password" {
  description = "SMTP password stored in Secrets Manager."
  type        = string
  sensitive   = true
  default     = ""
}

variable "ai_openai_api_key" {
  description = "Optional OpenAI key stored in Secrets Manager."
  type        = string
  sensitive   = true
  default     = ""
}

variable "jwt_access_token_expiration" {
  description = "Access token expiration in milliseconds."
  type        = number
  default     = 900000
}

variable "jwt_refresh_token_expiration" {
  description = "Refresh token expiration in milliseconds."
  type        = number
  default     = 604800000
}

variable "log_group_retention_days" {
  description = "Retention period for CloudWatch application logs."
  type        = number
  default     = 14
}
