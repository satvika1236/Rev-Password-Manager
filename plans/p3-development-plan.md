# P3 Development Plan: Rev Password Manager Modernization

Project: `P3-RevPasswordManager`  
Project title: `End-to-End Modernization of Password Manager Monolithic Secure Vault to Cloud-Native Microservices`  
Document type: `Development plan`  
Purpose: Turn the project brief into a development-ready roadmap that is simple to follow, technically robust, and aligned with the current codebase

---

## 1. Plan Objective

This plan is built for development execution, not just architecture presentation.

It does three things:

1. keeps the original project brief intact:
   - Phase 1: Containerization, CI/CD, and AWS deployment
   - Phase 2: Microservices transformation and local Kubernetes orchestration
2. simplifies the work into smaller sub-phases that developers can execute in order
3. adjusts sequencing based on the actual codebase so the migration is realistic and less risky

---

## 2. Planning Assumptions

These assumptions make the project easier to build and easier to defend during reviews.

### 2.1 Scope assumptions

- The current product features remain the same during migration.
- The Angular frontend should continue to use the same external API paths during most of the work.
- The existing secure sharing feature exists in the codebase, but it is not part of the original five-service project brief.
- For Project 3 scope, secure sharing remains inside the Vault domain unless time permits a later split.

### 2.2 Technology assumptions

- The project brief says Java 17.
- The current repository is already using Java 21.
- Before implementation starts, the team must make one decision:
  - either standardize the codebase down to Java 17 for rubric alignment
  - or formally keep Java 21 and document the reason

Recommended approach:

- If the evaluator requires Java 17, standardize early in Pre-Phase 0.
- If there is no strict runtime constraint, keep Java 21 and avoid unnecessary churn.

### 2.3 Architecture assumptions

- Public API paths should remain stable behind an API Gateway.
- Each extracted service should own its own schema and repository layer.
- OpenFeign will be used for service-to-service calls because it is part of the project brief and simpler for the first implementation.
- Kubernetes is a Phase 2 concern only. Do not start with Kubernetes before service boundaries are clear.

---

## 3. High-Level Delivery Strategy

This project should not be executed as a big-bang rewrite.

The safest sequence is:

1. stabilize and clean the monolith
2. containerize and deploy the monolith
3. harden internal boundaries in the monolith
4. build shared Spring Cloud platform components
5. extract services one by one
6. run the microservices locally on Minikube
7. add monitoring, logging, and tracing after services are stable

This strategy gives the team:

- working software at the end of every major phase
- easier debugging
- simpler rollback
- clearer demos

---

## 4. Target End State for Project 3

The project brief defines five business microservices, but the final running system is larger than five services once platform services are included.

To avoid confusion, this plan uses three counts.

### 4.1 Core business microservices required by the project brief

These are the five services the team should guarantee for Project 3 delivery:

1. User Service
   - authentication, profile, settings, sessions, 2FA, recovery
2. Vault Service
   - vault CRUD, folders, categories, favorites, trash, password history, vault snapshots, import, export, backup restore, sensitive view, secure sharing in minimum scope
3. Generator Service
   - password generation and strength checking
4. Security Service
   - audit logs, alerts, login history, password analysis, dashboard metrics, timeline in minimum scope
5. Notification Service
   - in-app notifications and email delivery

### 4.2 Platform and supporting services

These are not business-domain services, but they are still runtime services in the final system:

1. API Gateway
2. Eureka Server
3. Config Server

That means the actual deployed system is already at least eight services:

1. User Service
2. Vault Service
3. Generator Service
4. Security Service
5. Notification Service
6. API Gateway
7. Eureka Server
8. Config Server

If you also count observability components, the local platform becomes even larger:

- Elasticsearch
- Logstash
- Kibana
- Prometheus
- Grafana

### 4.3 Optional advanced business splits

If the team wants a cleaner domain model than the strict five-service brief, the codebase can justify two additional business services:

6. Sharing Service
7. Analytics Service

#### Sharing Service

Scope:

- secure share creation
- share token lifecycle
- share expiration
- share revocation
- public share access

#### Analytics Service

Scope:

- dashboard metrics
- timeline aggregation
- read-model style security reporting

### 4.4 Recommended interpretation for this project

Use this rule:

- for rubric alignment, deliver at least the five required business microservices
- for architecture discussion, clearly state that the full runtime system contains more than five services because of Gateway, Eureka, and Config Server
- if time permits and the team wants a stronger design, split Sharing out of Vault as a sixth business service

### 4.5 Practical scope note

To keep development robust:

- the minimum guaranteed implementation remains the five required business microservices
- secure sharing may stay under Vault Service for minimum scope, or move into a dedicated Sharing Service as an extended scope improvement
- schedulers stay inside the service that owns the data
- the frontend stays as one Angular application and talks only to the Gateway

---

## 5. Service Ownership Model

### 5.1 Minimum Project 3 ownership model

| Service | Core responsibility | Primary routes | Main data owned |
|---|---|---|---|
| User Service | auth, profile, settings, sessions, 2FA, recovery | `/api/auth/**`, `/api/users/**`, `/api/settings/**`, `/api/2fa/**`, `/api/sessions/**` | users, user_settings, user_sessions, two_factor_auth, otp_tokens, recovery_codes, security_questions |
| Vault Service | vault CRUD, folders, categories, trash, snapshots, backup, sensitive view, secure sharing in minimum scope | `/api/vault/**`, `/api/categories/**`, `/api/folders/**`, `/api/backup/**`, `/api/shares/**` | vault_entries, folders, categories, vault_snapshots, backup_exports, secure_shares |
| Security Service | audit logs, alerts, login history, password analysis, dashboard metrics, timeline in minimum scope | `/api/security/**`, `/api/dashboard/**`, `/api/timeline/**` | audit_logs, security_alerts, login_attempts, password_analysis, security_metrics_history |
| Generator Service | password generation and strength check | `/api/generator/**` | no major state required or optional generation audit table |
| Notification Service | in-app notifications and email delivery | `/api/notifications/**` | notifications |

### 5.1.1 Explicit feature mapping for vault-related capabilities

The following features are owned by `Vault Service` in this plan:

- vault entry create, update, delete, restore
- folders and categories
- favorites
- trash and trash cleanup
- password history
- vault snapshots
- backup export
- backup import
- snapshot restore
- secure view of sensitive entries
- secure sharing in the minimum five-service scope

Reason:

- these features all read or write vault-owned encrypted data
- they depend on vault tables directly
- they should stay with the service that owns vault encryption and vault persistence

Important note about the original project brief:

- the brief places `export/import encrypted backups` under Security Service
- for actual implementation, this plan moves them to `Vault Service`
- this is the safer design because import/export operates on vault entries, folders, categories, and snapshots, not just on security reporting

### 5.2 Extended ownership model if you go beyond five business services

| Service | Core responsibility | Primary routes | Main data owned |
|---|---|---|---|
| Sharing Service | secure share creation, token lifecycle, expiry, revoke, public access | `/api/shares/**` | secure_shares |
| Analytics Service | dashboard metrics, timeline aggregation, reporting read models | `/api/dashboard/**`, `/api/timeline/**` | dashboard read models, timeline read models, analytics projections |

---

## 6. Phase Overview

| Phase | Goal | Duration | Main output |
|---|---|---|---|
| Pre-Phase 0 | baseline cleanup and planning | 1 week | stable starting point |
| Phase 1 | containerize monolith and deploy to AWS | 4 to 5 weeks | production-ready monolith on AWS |
| Phase 2A | prepare monolith for extraction | 2 weeks | clean internal boundaries |
| Phase 2B | build Spring Cloud platform foundation | 1 to 2 weeks | gateway, discovery, config, templates |
| Phase 2C | extract core business services | 5 to 7 weeks | five required business services running locally |
| Phase 2C-Extended | optional additional business service splits | 1 to 3 weeks | sixth and seventh business services if chosen |
| Phase 2D | local Kubernetes and observability | 2 weeks | full local microservices platform |

Total estimate: 15 to 18 weeks depending on team size and test maturity.

---

## 7. Pre-Phase 0: Baseline Cleanup and Alignment

This phase is not part of the original brief, but it is necessary if the team wants a clean execution path.

### 7.1 Sub-phase: Runtime and dependency alignment

Tasks:

- decide Java baseline: 17 or 21
- align backend Dockerfile, Maven compiler version, and CI toolchain
- align frontend Node version across Docker, local dev, and CI

Deliverables:

- agreed runtime matrix
- updated README setup instructions

Exit criteria:

- every developer can run backend and frontend locally with the same versions

### 7.2 Sub-phase: Secrets and config cleanup

Tasks:

- remove hardcoded database, JWT, and mail secrets from source files
- move secrets to environment variables
- standardize config profiles:
  - local
  - docker
  - aws

Deliverables:

- `.env.example`
- documented config matrix

Exit criteria:

- no production secrets in git-tracked files

### 7.3 Sub-phase: Baseline testing

Tasks:

- create a smoke test checklist for critical flows
- ensure backend tests pass consistently
- ensure frontend tests for auth, dashboard, and vault are runnable

Critical flows:

- register
- login
- refresh token
- 2FA setup
- create vault entry
- view sensitive vault entry
- generate password
- export backup
- create and read notification

Deliverables:

- smoke test document
- stable baseline test run

Exit criteria:

- team has a known-good baseline before migration starts

---

## 8. Phase 1: Containerization, CI/CD, and AWS Deployment

Goal: Deploy the current monolith in a clean, repeatable, cloud-ready way before any service extraction begins.

## Phase 1.1: Container-ready monolith

Tasks:

- finalize backend multi-stage Dockerfile
- finalize frontend multi-stage Dockerfile
- create or clean up Docker Compose for:
  - mysql
  - backend
  - frontend
- verify health checks
- verify file storage and logs volume mounting

Deliverables:

- working backend image
- working frontend image
- working Docker Compose stack

Done criteria:

- one command starts the full application locally in containers

## Phase 1.2: AWS infrastructure setup

Tasks:

- provision VPC and subnets
- provision security groups
- provision RDS MySQL Multi-AZ
- provision ECR repositories
- provision EC2 Auto Scaling Group for backend
- provision Application Load Balancer

Recommended implementation approach:

- use Terraform or CloudFormation
- keep infrastructure code in version control

Deliverables:

- AWS infrastructure as code
- test database on RDS
- backend instances registered behind ALB

Done criteria:

- backend is reachable through ALB
- database is running on RDS

## Phase 1.3: Secrets and cloud configuration

Tasks:

- create AWS Secrets Manager entries
- wire Spring configuration to load secrets from environment or AWS
- separate local config from AWS config

Deliverables:

- cloud-safe config
- secret rotation checklist

Done criteria:

- AWS deployment does not require hardcoded credentials

## Phase 1.4: Jenkins CI/CD pipeline

Tasks:

- Jenkins Git checkout stage
- Maven build stage
- backend test stage
- SonarQube analysis stage
- Docker image build stage
- image push to ECR stage
- deployment stage to EC2 or ASG refresh

Pipeline quality gates:

- build must fail on test failure
- build must fail on image build failure
- deployment should happen only after successful build and analysis

Deliverables:

- Jenkinsfile
- working CI/CD job

Done criteria:

- a push to main triggers a full build and deploy flow

## Phase 1.5: Production hardening and validation

Tasks:

- add Actuator health checks
- verify ALB target health
- verify logs are collected
- run smoke tests against AWS deployment
- document rollback process

Deliverables:

- deployment validation report
- rollback checklist

Done criteria:

- monolith is production-like and stable on AWS

---

## 9. Phase 2: Microservices Transformation and Local Kubernetes Orchestration

Goal: Refactor the monolith into the five required services and run them locally on Minikube with full routing, config, and observability.

To keep the work manageable, Phase 2 is split into four major blocks:

- Phase 2A: prepare the monolith
- Phase 2B: build shared platform components
- Phase 2C: extract services in a safe order
- Phase 2D: run on Minikube and add observability

---

## 10. Phase 2A: Prepare the Monolith for Extraction

This block reduces risk before any code is moved into separate services.

## Phase 2A.1: Identify bounded contexts and internal modules

Tasks:

- group backend packages into five target service boundaries
- map controllers to target services
- map entities and repositories to target services
- document which classes currently cross service boundaries

Deliverables:

- service mapping table
- dependency hotspot list

Done criteria:

- every controller and table has a target owner

## Phase 2A.2: Refactor for clean boundaries

Tasks:

- create internal facade interfaces inside the monolith
- reduce direct cross-domain repository access
- isolate crypto operations under vault-owned code
- isolate email sending under notification-owned code
- isolate auth/session logic under user-owned code

Deliverables:

- cleaner package boundaries
- fewer direct cross-domain method calls

Done criteria:

- extraction can happen by module rather than by random class movement

## Phase 2A.3: Stabilize API contracts

Tasks:

- list the exact current public routes
- freeze external route names
- generate or clean up the authoritative OpenAPI contract
- regenerate Angular API client from the real backend contract

Deliverables:

- stable API contract
- frontend client aligned with backend

Done criteria:

- frontend uses the correct contract before extraction begins

---

## 11. Phase 2B: Build the Shared Spring Cloud Platform

This block creates the infrastructure required by the project brief.

## Phase 2B.1: API Gateway

Tasks:

- create Spring Cloud Gateway project
- define route mappings for existing API paths
- add CORS
- add request logging
- add Resilience4j circuit breaker integration
- add edge rate limiting

Deliverables:

- gateway service
- route config

Done criteria:

- frontend can call the gateway and reach the monolith through it

## Phase 2B.2: Eureka Server

Tasks:

- create Eureka Server
- register sample service
- verify service discovery flow

Deliverables:

- running discovery server

Done criteria:

- extracted services can register and be discovered

## Phase 2B.3: Config Server

Tasks:

- create Config Server
- move service configs to centralized config repo or config source
- define per-service profiles:
  - local
  - minikube
  - test

Deliverables:

- running config server
- centralized service configuration

Done criteria:

- services can bootstrap using centralized config

## Phase 2B.4: Shared service template

Tasks:

- create a base service template with:
  - actuator
  - logging config
  - OpenAPI
  - resilience config
  - security config pattern
  - test template

Deliverables:

- reusable microservice starter template

Done criteria:

- each new service can be created from the same template

---

## 12. Phase 2C: Extract Services

The extraction order below is chosen for development safety, not just domain naming.

Recommended extraction order for the minimum five-service implementation:

1. Notification Service
2. User Service
3. Vault Service
4. Security Service
5. Generator Service

### Why this order

- Notification is lowest risk and gives fast experience with service extraction.
- User is high value and central to auth.
- Vault is the core business service and should only be extracted after boundaries are cleaner.
- Security depends on data from User and Vault, so it should come after them.
- Generator is mostly stateless and easiest to extract last.

### Optional extended extraction order

If the team decides to go beyond five business microservices, use this order after the core five are stable:

6. Sharing Service
7. Analytics Service

## Phase 2C.1: Notification Service extraction

Tasks:

- move notification controller and service
- move notification repository and model
- move email service if fully notification-owned
- expose `/api/notifications/**`
- connect frontend notification bell to gateway route

Deliverables:

- standalone notification service

Done criteria:

- notification polling and mark-read flows work through gateway

## Phase 2C.2: User Service extraction

Scope:

- authentication
- profile
- settings
- 2FA
- security questions
- account recovery
- session management
- logout

Tasks:

- move auth-related controllers and services
- move user-related entities and repositories
- move JWT issuance and refresh logic
- expose routes through gateway
- create Feign clients where other services need user context

Deliverables:

- standalone user service

Done criteria:

- login, logout, refresh token, profile, settings, 2FA, and sessions work through gateway

## Phase 2C.3: Vault Service extraction

Scope:

- vault CRUD
- search and filter
- categories
- folders
- favorites
- sensitive view
- trash
- snapshots
- backup export and import
- secure sharing for minimum Project 3 scope

Tasks:

- move vault controllers and services
- move vault entities and repositories
- isolate encryption logic inside vault-owned code
- expose routes through gateway
- connect frontend vault and backup screens to gateway

Deliverables:

- standalone vault service

Done criteria:

- vault, folders, categories, trash, history, sharing, backup all work through gateway

## Phase 2C.4: Security Service extraction

Scope:

- audit logs
- login history
- security alerts
- password analysis
- dashboard metrics
- verification-related security helpers that belong outside User Service

Tasks:

- move security controller and dashboard controller
- move audit, login attempt, alert, and analysis entities
- expose routes through gateway
- add Feign clients to User and Vault where immediate data is required
- connect frontend dashboard and security settings screens to gateway

Deliverables:

- standalone security service

Done criteria:

- dashboard, audit logs, login history, and security alerts all work through gateway

## Phase 2C.5: Generator Service extraction

Scope:

- password generation
- strength analysis
- default generation settings

Tasks:

- move generator controller and related services
- expose `/api/generator/**`
- connect frontend password generator widget through gateway

Deliverables:

- standalone generator service

Done criteria:

- generator endpoints work independently and are routed through gateway

## Phase 2C-Extended: Optional additional business service splits

This block is optional. Use it only if:

- the project evaluator accepts more than five business microservices
- the team has enough time after the core extraction is stable

## Phase 2C-Extended.1: Sharing Service extraction

Tasks:

- move secure share controller and service out of Vault
- move `secure_shares` ownership into Sharing Service
- expose `/api/shares/**` through gateway
- connect Sharing Service to Vault Service using Feign

Deliverables:

- standalone sharing service

Done criteria:

- secure share creation, revoke, expiry, and public access work independently from Vault API ownership

## Phase 2C-Extended.2: Analytics Service extraction

Tasks:

- move dashboard and timeline logic out of Security Service
- create read-model style analytics endpoints
- expose `/api/dashboard/**` and `/api/timeline/**` through gateway
- connect Analytics Service to User, Vault, and Security data via Feign or event-fed projections

Deliverables:

- standalone analytics service

Done criteria:

- dashboard and timeline are separated from core security operations

---

## 13. Phase 2D: Local Kubernetes and Observability

After the services are working in local or Docker-based development, move them into Minikube.

## Phase 2D.1: Containerize every microservice

Tasks:

- add Dockerfile per service
- add service-level health checks
- verify configuration via Config Server

Deliverables:

- deployable images for all services

Done criteria:

- all services can run in Docker locally

## Phase 2D.2: Minikube deployment

Tasks:

- create Deployment manifests
- create Service manifests
- create ConfigMaps
- create Secrets
- create Ingress
- create HPA for main services

Deliverables:

- working Minikube cluster definition

Done criteria:

- frontend and all microservices run together on Minikube

## Phase 2D.3: Logging, monitoring, and tracing

Tasks:

- add ELK stack locally
- expose Prometheus scrape targets
- build Grafana dashboards
- add application metrics
- add distributed tracing headers and tracing visualization

Deliverables:

- centralized logs
- metrics dashboards
- trace visibility

Done criteria:

- service behavior can be observed end-to-end locally

## Phase 2D.4: Final hardening and demo preparation

Tasks:

- run full smoke tests against Minikube
- verify gateway routing
- verify service registration
- verify config loading
- verify fault tolerance behavior
- verify dashboards and logs
- prepare demo scripts and architecture diagrams

Deliverables:

- final demo-ready platform
- deployment checklist
- architecture presentation material

Done criteria:

- the entire project can be demonstrated reliably from start to finish

---

## 14. Frontend Development Plan

The frontend should evolve with the backend, not be rewritten.

### Frontend rule 1

The Angular app should always talk to one base URL only:

- monolith directly in early development
- API Gateway after Phase 2B

### Frontend rule 2

Regenerate the OpenAPI client after each service extraction milestone.

### Frontend rule 3

Keep route structure stable:

- login
- dashboard
- vault
- backup
- profile
- share access

### Frontend tasks by stage

During Phase 1:

- clean environment configuration
- ensure Docker production build works
- keep frontend same-origin ready

During Phase 2A:

- stabilize API client generation
- remove stale generated endpoints

During Phase 2C:

- switch all API calls to gateway
- verify feature-by-feature routing
- update tests where response owners change

During Phase 2C-Extended:

- update sharing and analytics frontend clients if those services are split out
- verify gateway ownership changes without changing Angular route structure

During Phase 2D:

- verify all flows on Minikube ingress
- validate notification polling and auth refresh behavior

---

## 15. Testing Plan

This project should be tested in layers.

### 15.1 Before service extraction

- unit tests for core services
- integration tests for auth, vault, and backup
- frontend component tests for login, dashboard, vault

### 15.2 During service extraction

- service-level unit tests
- service-level integration tests
- gateway route tests
- Feign client integration tests
- frontend smoke tests against gateway

### 15.3 Before Minikube finalization

- full end-to-end smoke suite:
  - register
  - login
  - refresh token
  - 2FA
  - create vault entry
  - search vault
  - generate password
  - export backup
  - read notifications

---

## 16. Definition of Done Per Phase

No phase should be marked complete unless:

- build passes
- tests pass
- documentation is updated
- configuration is externalized
- deployment path is repeatable
- rollback steps are written

---

## 17. Key Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Java version mismatch between spec and repo | build and demo instability | decide runtime baseline in Pre-Phase 0 |
| extracting Vault too early | crypto and data breakage | extract Vault only after boundary cleanup |
| stale frontend API client | broken UI after extraction | freeze API contract and regenerate clients frequently |
| AWS setup delays | Phase 1 demo blocked | provision infrastructure early and test incrementally |
| too many platform tools added at once | team loses time in setup | add gateway, config, discovery first, then observability |
| Kubernetes added too early | debugging becomes hard | finish service extraction before Minikube orchestration |

---

## 18. Recommended Team Workflow

### Branching

- `main` for stable release-ready code
- short-lived feature branches per sub-phase

### Work breakdown

- Backend developer 1: User and Security domains
- Backend developer 2: Vault and Generator domains
- Frontend developer: Angular integration and gateway routing
- DevOps owner: Docker, Jenkins, AWS, Minikube, observability

### Demo cadence

Demo after:

- Phase 1.2
- Phase 1.4
- Phase 2B
- each service extraction
- final Minikube integration

---

## 19. Final Recommended Execution Order

If the team wants the simplest and most robust development path, follow this exact order:

1. Pre-Phase 0 cleanup
2. Phase 1 monolith containerization
3. Phase 1 AWS deployment
4. Phase 1 Jenkins CI/CD
5. Phase 2A internal boundary cleanup
6. Phase 2B gateway, config server, and Eureka
7. Notification Service extraction
8. User Service extraction
9. Vault Service extraction
10. Security Service extraction
11. Generator Service extraction
12. optional Sharing Service extraction
13. optional Analytics Service extraction
14. Minikube deployment
15. Observability integration
16. final smoke testing and demo preparation

This gives you a development plan that matches the project brief, makes it clear why the total system is larger than five services, and still keeps the implementation practical.
