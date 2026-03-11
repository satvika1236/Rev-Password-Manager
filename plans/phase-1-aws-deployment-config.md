# Phase 1 AWS Deployment Config

This document records the Phase 1 AWS deployment contract implemented in-repo.

## Terraform entry point

- Directory: `infra/aws`
- Primary command flow:
  - `terraform init`
  - `terraform plan -var-file=terraform.tfvars`
  - `terraform apply -var-file=terraform.tfvars`

## Provisioned infrastructure

- VPC with two public subnets and two private subnets
- One Internet Gateway and one NAT Gateway
- Application Load Balancer
- Two target groups:
  - frontend on port `80`
  - backend on port `8080`
- Auto Scaling Group running Amazon Linux 2023 EC2 instances
- MySQL 8 RDS Multi-AZ instance
- Two ECR repositories:
  - backend
  - frontend
- Two Secrets Manager entries:
  - `/<project>-<environment>/database`
  - `/<project>-<environment>/application`
- One CloudWatch log group for container logs

## Runtime profile contract

The EC2 bootstrap writes a runtime `.env` file for Docker Compose and starts the containers with:

- `SPRING_PROFILES_ACTIVE=aws`
- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `JWT_SECRET`
- `JWT_ACCESS_TOKEN_EXPIRATION`
- `JWT_REFRESH_TOKEN_EXPIRATION`
- `SPRING_MAIL_HOST`
- `SPRING_MAIL_PORT`
- `SPRING_MAIL_USERNAME`
- `SPRING_MAIL_PASSWORD`
- `AI_OPENAI_API_KEY`
- `CORS_ALLOWED_ORIGINS`
- `LOGGING_FILE_NAME=/app/logs/password-manager.log`
- `SECURE_FILES_STORAGE_PATH=/app/secure-files`

## Health checks

- Frontend container health: `/healthz`
- Backend container health: `/actuator/health`
- ALB frontend target group health path: `/healthz`
- ALB backend target group health path: `/actuator/health`

## Jenkins variables

The checked-in `Jenkinsfile` expects these environment variables to be configured in Jenkins:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `ECR_BACKEND_REPOSITORY`
- `ECR_FRONTEND_REPOSITORY`
- `ASG_NAME`
- `SONARQUBE_ENV` if SonarQube analysis is enabled

## Apply-time notes

- Replace placeholder values in `terraform.tfvars.example` before apply.
- The current Terraform uses one NAT Gateway for lower complexity. It is sufficient for Phase 1 but not a full HA network design.
- The current CI/CD flow deploys by pushing `latest` and triggering an ASG instance refresh. Rollback is documented separately.
