# Rev Password Manager

Rev Password Manager is a full-stack password manager built with Angular 18, Spring Boot 3, and MySQL 8.

## Stack

Backend:

- Java 21
- Spring Boot 3.2.3
- Spring Security
- Spring Data JPA
- Spring Mail
- SpringDoc OpenAPI
- Maven 3.9+

Frontend:

- Angular 18
- Angular Material
- TypeScript 5.5
- Karma + Jasmine
- Node.js 20.x
- npm 10.x

Infrastructure:

- Docker
- Docker Compose
- Nginx
- MySQL 8.0
- Terraform
- Jenkins

## Pre-Phase 0 baseline

The repository now uses three backend profiles:

- `local`: default profile for manual development.
- `docker`: used by `docker compose`.
- `aws`: reserved for cloud deployment.

Reference documents:

- [Runtime and config matrix](plans/pre-phase-0-runtime-config-matrix.md)
- [Smoke test checklist](plans/pre-phase-0-smoke-test-checklist.md)
- [P3 development plan](plans/p3-development-plan.md)
- [P3 todo list](plans/p3-todo-list.md)
- [Phase 1 next steps runbook](plans/phase-1-next-steps-runbook.md)
- [Phase 1 AWS deployment config](plans/phase-1-aws-deployment-config.md)
- [Phase 1 secret rotation checklist](plans/phase-1-secret-rotation-checklist.md)
- [Phase 1 deployment validation report](plans/phase-1-deployment-validation-report.md)
- [Phase 1 rollback checklist](plans/phase-1-rollback-checklist.md)

## Prerequisites

| Tool | Version |
|---|---|
| Java JDK | 21 |
| Maven | 3.9+ |
| Node.js | 20.x |
| npm | 10.x |
| MySQL | 8.0 |
| Docker | 24+ |
| Docker Compose | 2.x |

## Local setup

1. Copy the environment template.

```bash
copy .env.example .env
```

2. Edit `.env` with your local database, JWT, and SMTP values.

3. Create the database.

```sql
CREATE DATABASE rev_password_manager;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON rev_password_manager.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
```

4. Start the backend from the project root.

```bash
mvn spring-boot:run
```

5. Start the frontend.

```bash
cd frontend
npm install
npm start
```

URLs:

- Frontend: `http://localhost:4200`
- Backend API: `http://localhost:8080/api`
- Swagger UI: `http://localhost:8080/swagger-ui.html`

Notes:

- The backend defaults to the `local` profile.
- Spring Boot imports the project-root `.env` file automatically.
- The frontend development server targets the backend on `http://localhost:8080`.

## Docker setup

1. Copy the template.

```bash
copy .env.example .env
```

2. Update any values you do not want to use from the local-safe defaults.

3. Start the stack.

```bash
docker compose up --build
```

URLs:

- Frontend: `http://localhost`
- Backend API: `http://localhost:8082/api`
- Swagger UI: `http://localhost:8082/swagger-ui.html`

Notes:

- Compose sets `SPRING_PROFILES_ACTIVE=docker`.
- MySQL, backend logs, and secure files are stored in named Docker volumes.
- Backend health is available at `http://localhost:8082/actuator/health`.
- Frontend health is available at `http://localhost/healthz`.

## Phase 1 deployment assets

Phase 1 infrastructure and delivery scaffolding now lives in:

- `infra/aws/` for Terraform-based AWS infrastructure.
- `deploy/aws/` for the EC2 runtime Docker Compose reference.
- `Jenkinsfile` for build, test, SonarQube, ECR push, and ASG refresh automation.

Suggested Phase 1 execution order:

1. Copy `infra/aws/terraform.tfvars.example` to a local tfvars file and replace placeholders.
2. Run `terraform init`, `terraform plan`, and `terraform apply` from `infra/aws`.
3. Configure the Jenkins environment variables listed in `plans/phase-1-aws-deployment-config.md`.
4. Push to `main` after Jenkins is connected to ECR and the Auto Scaling Group.

## Environment variables

`.env.example` is the only tracked template. Keep `.env` local-only.

Key variables:

```env
SPRING_PROFILES_ACTIVE=local

MYSQL_DATABASE=rev_password_manager
MYSQL_ROOT_PASSWORD=changeit-root-password
MYSQL_USER=appuser
MYSQL_PASSWORD=changeit-app-password

SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/rev_password_manager?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
SPRING_DATASOURCE_USERNAME=appuser
SPRING_DATASOURCE_PASSWORD=changeit-app-password

JWT_SECRET=replace_with_at_least_32_characters_before_sharing
JWT_ACCESS_TOKEN_EXPIRATION=900000
JWT_REFRESH_TOKEN_EXPIRATION=604800000

SPRING_MAIL_HOST=localhost
SPRING_MAIL_PORT=1025
SPRING_MAIL_USERNAME=
SPRING_MAIL_PASSWORD=

AI_OPENAI_API_KEY=
CORS_ALLOWED_ORIGINS=http://localhost,http://localhost:4200,http://localhost:8080
```

SMTP note:

- For local development, use a fake SMTP server such as MailHog unless you intentionally want to send real email.

## Tests

Backend:

```bash
mvn test
mvn verify
```

Frontend:

```bash
cd frontend
npm test -- --watch=false --browsers=ChromeHeadless
```

## Major API groups

- `/api/auth/**`
- `/api/users/**`
- `/api/settings/**`
- `/api/2fa/**`
- `/api/sessions/**`
- `/api/vault/**`
- `/api/categories/**`
- `/api/folders/**`
- `/api/backup/**`
- `/api/dashboard/**`
- `/api/security/**`
- `/api/notifications/**`
- `/api/shares/**`

## Project structure

```text
Rev-PasswordManager/
|-- frontend/
|-- plans/
|-- src/
|   |-- main/
|   |   |-- java/
|   |   `-- resources/
|   `-- test/
|-- .env.example
|-- docker-compose.yml
|-- Dockerfile
`-- pom.xml
```

## Security and repository hygiene

- Real secrets must not be committed to tracked source files.
- `.env`, logs, build output, Sonar output, coverage output, and `node_modules` are treated as generated/local artifacts.
- If sensitive values were committed previously, rotate them outside the repository. Phase 0 cleanup only removes them from the current tracked baseline; it does not rewrite repository history.
