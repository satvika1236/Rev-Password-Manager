# Phase 1 Next Steps Runbook

This is the step-by-step flow to take the current repository from local verification to AWS deployment and Jenkins automation.

The commands below assume Windows PowerShell and this project root:

```powershell
Set-Location 'C:\Users\mulac\manager\Rev-PasswordManager (2)\Rev-PasswordManager'
```

## 1. Install what you need

Required tools:

- Git for Windows
- Java JDK 21
- Maven 3.9+
- Node.js 20.x and npm 10.x
- Docker Desktop with Docker Compose
- Google Chrome or Chromium for frontend headless tests
- AWS CLI v2
- Terraform 1.8+ or use the Docker-based Terraform flow below

Optional tools:

- Jenkins LTS
- SonarQube

Recommended versions used by this repo:

- Java 21
- Node 20
- npm 10
- Docker Compose v2
- Terraform 1.8+

After installing, verify your toolchain:

```powershell
git --version
java -version
mvn -version
node -v
npm -v
docker --version
docker compose version
aws --version
terraform -version
```

If `terraform` is not installed locally, that is fine. Use the Docker-based Terraform commands in section 6.

Windows PowerShell notes:

- If Maven reports that `JAVA_HOME` is not defined, set it first:

```powershell
$env:JAVA_HOME='C:\Program Files\Java\jdk-21'
```

- If PowerShell blocks `npm.ps1`, use `npm.cmd` instead of `npm` for the commands below:

```powershell
& 'C:\Program Files\nodejs\npm.cmd' -v
```

## 2. Prepare local secrets and config

Create a fresh local `.env` file from the tracked template:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and replace placeholder values before you keep working.

Minimum values you should review:

- `JWT_SECRET`
- `MYSQL_ROOT_PASSWORD`
- `MYSQL_PASSWORD`
- `SPRING_MAIL_HOST`
- `SPRING_MAIL_PORT`
- `SPRING_MAIL_USERNAME`
- `SPRING_MAIL_PASSWORD`
- `AI_OPENAI_API_KEY`

Rules:

- Do not commit `.env`
- Do not reuse old leaked or shared passwords
- Keep `SPRING_PROFILES_ACTIVE=local` for local dev

## 3. Local verification flow

### 3.1 Backend tests

If Java is not already on `PATH`, set `JAVA_HOME` first:

```powershell
$env:JAVA_HOME='C:\Program Files\Java\jdk-21'
mvn test -q
```

Expected result:

- backend tests pass

### 3.2 Frontend install and tests

```powershell
Set-Location .\frontend
npm install
npm test -- --watch=false --browsers=ChromeHeadless
Set-Location ..
```

If PowerShell execution policy blocks `npm`, run the same commands with `npm.cmd`:

```powershell
Set-Location .\frontend
& 'C:\Program Files\nodejs\npm.cmd' install
& 'C:\Program Files\nodejs\npm.cmd' test -- --watch=false --browsers=ChromeHeadless
Set-Location ..
```

Expected result:

- frontend tests pass

### 3.3 Container image builds

```powershell
docker compose build backend frontend
```

Expected result:

- backend image builds
- frontend image builds

### 3.4 Full local container stack

```powershell
docker compose up -d
docker compose ps
```

Useful checks:

```powershell
Invoke-WebRequest http://localhost/healthz
Invoke-WebRequest http://localhost:8082/actuator/health
```

Useful logs:

```powershell
docker compose logs backend --tail 200
docker compose logs frontend --tail 100
docker compose logs mysql --tail 100
```

Stop the stack when finished:

```powershell
docker compose down
```

Expected URLs:

- Frontend: `http://localhost`
- Backend API: `http://localhost:8082/api`
- Backend health: `http://localhost:8082/actuator/health`
- Swagger UI: `http://localhost:8082/swagger-ui.html`

## 4. AWS account prerequisites

Before touching Terraform or Jenkins, make sure you have:

- an AWS account and region chosen for Phase 1
- IAM permissions for:
  - VPC
  - EC2
  - Auto Scaling
  - Elastic Load Balancing v2
  - RDS
  - ECR
  - IAM
  - Secrets Manager
  - CloudWatch Logs
  - SSM
- an AWS CLI profile configured locally

Configure AWS CLI if needed:

```powershell
aws configure
aws sts get-caller-identity
```

Write down:

- AWS account ID
- AWS region

## 5. Prepare Terraform inputs

Copy the example variables file:

```powershell
Copy-Item .\infra\aws\terraform.tfvars.example .\infra\aws\terraform.tfvars
```

Open `infra/aws/terraform.tfvars` and update at least:

- `project_name`
- `environment`
- `aws_region`
- `app_domain_name` if you have one
- `frontend_allowed_origins`
- `instance_type`
- `min_size`
- `max_size`
- `desired_capacity`
- `db_name`
- `db_username`
- `db_instance_class`
- `mail_host`
- `mail_port`
- `mail_username`
- `mail_password`
- `ai_openai_api_key`

Rules:

- Do not commit `terraform.tfvars`
- Commit `.terraform.lock.hcl`

## 6. Run Terraform

### Option A: Local Terraform installed

```powershell
Set-Location .\infra\aws
terraform fmt -recursive
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
terraform output
Set-Location ..\..
```

### Option B: No local Terraform installed

Run Terraform from the official Docker image:

```powershell
$repo = (Get-Location).Path
docker run --rm --entrypoint /bin/sh -v "${repo}:/work" -w /work/infra/aws hashicorp/terraform:1.8.5 -lc "terraform fmt -recursive && terraform init && terraform plan -var-file=terraform.tfvars"
docker run --rm --entrypoint /bin/sh -v "${repo}:/work" -w /work/infra/aws hashicorp/terraform:1.8.5 -lc "terraform apply -var-file=terraform.tfvars"
docker run --rm --entrypoint /bin/sh -v "${repo}:/work" -w /work/infra/aws hashicorp/terraform:1.8.5 -lc "terraform output"
```

Capture these Terraform outputs after apply:

- `alb_dns_name`
- `frontend_url`
- `backend_health_url`
- `rds_endpoint`
- `backend_ecr_repository_url`
- `frontend_ecr_repository_url`
- `asg_name`
- `database_secret_name`
- `application_secret_name`

## 7. Manual image push before Jenkins

This step is useful once to prove ECR and the launch path work before relying on Jenkins.

Set variables:

```powershell
$AWS_ACCOUNT_ID = aws sts get-caller-identity --query Account --output text
$AWS_REGION = 'us-east-1'
$BACKEND_REPO = 'password-manager-phase1-backend'
$FRONTEND_REPO = 'password-manager-phase1-frontend'
$TAG = 'manual-smoke-1'
```

If your `project_name` or `environment` in Terraform differ from the defaults, change `BACKEND_REPO` and `FRONTEND_REPO` to match.

Login to ECR:

```powershell
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
```

Build and tag:

```powershell
docker build -t "password-manager-backend:$TAG" .
docker build -t "password-manager-frontend:$TAG" .\frontend

docker tag "password-manager-backend:$TAG" "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$BACKEND_REPO:$TAG"
docker tag "password-manager-backend:$TAG" "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$BACKEND_REPO:latest"
docker tag "password-manager-frontend:$TAG" "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$FRONTEND_REPO:$TAG"
docker tag "password-manager-frontend:$TAG" "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$FRONTEND_REPO:latest"
```

Push:

```powershell
docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$BACKEND_REPO:$TAG"
docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$BACKEND_REPO:latest"
docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$FRONTEND_REPO:$TAG"
docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$FRONTEND_REPO:latest"
```

Trigger a rolling deploy:

```powershell
aws autoscaling start-instance-refresh --region $AWS_REGION --auto-scaling-group-name "<your-asg-name>" --preferences '{"MinHealthyPercentage":50,"InstanceWarmup":180}'
```

## 8. Jenkins setup flow

If Jenkins is not already available, set up Jenkins LTS first.

Install these Jenkins plugins before using the checked-in `Jenkinsfile`:

- Pipeline
- Git
- JUnit
- Credentials Binding
- Docker Pipeline or equivalent Docker access
- SonarQube Scanner for Jenkins if you want the Sonar stage
- AWS Credentials or another supported AWS auth method

In Jenkins, create a pipeline job that points at this repository and uses the checked-in `Jenkinsfile`.

Set these Jenkins environment variables:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `ECR_BACKEND_REPOSITORY`
- `ECR_FRONTEND_REPOSITORY`
- `ASG_NAME`
- `SONARQUBE_ENV` if you have SonarQube configured

Quick ways to get the values:

- `AWS_ACCOUNT_ID`:

```powershell
aws sts get-caller-identity --query Account --output text
```

- `ASG_NAME`:

```powershell
Set-Location .\infra\aws
terraform output -raw asg_name
Set-Location ..\..
```

Default repository names if you kept default Terraform values:

- `password-manager-phase1-backend`
- `password-manager-phase1-frontend`

Pipeline behavior:

1. Checkout code
2. Build backend
3. Run backend tests
4. Run SonarQube analysis if configured
5. Build backend and frontend Docker images
6. Push images to ECR on `main`
7. Trigger ASG instance refresh on `main`

## 9. Post-deploy validation flow

After Terraform apply and image push, run these checks.

Replace `<alb-dns>` with the actual value from Terraform output.

```powershell
Invoke-WebRequest "http://<alb-dns>/healthz"
Invoke-WebRequest "http://<alb-dns>/actuator/health"
```

You should also manually verify:

- frontend root page loads
- login works
- vault page loads
- create vault entry works
- backup export works
- logout works

Use these documents while validating:

- `plans/phase-1-deployment-validation-report.md`
- `plans/phase-1-rollback-checklist.md`
- `plans/phase-1-secret-rotation-checklist.md`

## 10. Recommended exact order

Run the next steps in this order:

1. Install required tools
2. Create fresh `.env`
3. Run backend tests
4. Run frontend tests
5. Build Docker images locally
6. Start local Docker Compose and smoke check it
7. Configure AWS CLI
8. Create `infra/aws/terraform.tfvars`
9. Run Terraform apply
10. Push a manual test image set to ECR
11. Trigger one manual ASG instance refresh
12. Validate the ALB URLs
13. Configure Jenkins
14. Push to `main` and verify the Jenkins pipeline

## 11. What is still manual after this

These items are still on you to execute outside the repo:

- installing Jenkins if you do not already have it
- running Terraform apply against AWS
- checking AWS billing impact before apply
- validating ALB target health in AWS
- confirming CloudWatch logs are clean
- running the first live AWS smoke test

## 12. If something fails

Useful commands:

```powershell
docker compose logs backend --tail 200
docker compose logs frontend --tail 100
docker compose logs mysql --tail 100
aws sts get-caller-identity
aws autoscaling describe-instance-refreshes --auto-scaling-group-name "<your-asg-name>" --region "<your-region>"
```

Use the rollback checklist here:

- `plans/phase-1-rollback-checklist.md`
