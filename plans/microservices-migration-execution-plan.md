# Password Manager Microservices Migration Execution Plan

Status: Recommended implementation plan  
Audience: Backend, frontend, DevOps, QA, and tech leads  
Scope: Replace the existing generic migration plan with a codebase-grounded execution plan  

---

## 1. Executive Summary

This plan is designed for the current codebase as it exists today:

- Backend: Spring Boot 3.2.x, Java 21, MySQL, JWT auth, JPA, scheduled jobs
- Frontend: Angular 18 SPA, generated OpenAPI client plus some manual `HttpClient` usage
- Current architecture: modular monolith with strong internal coupling, especially around vault encryption, security analysis, sharing, and user/session state

The goal is not to maximize the number of microservices. The goal is to create a migration path that is:

- safe
- understandable
- incremental
- testable
- easy for the team to develop
- realistic for the current encryption and data model

This plan intentionally avoids premature splits that would create high operational complexity without reducing risk.

### Recommended target architecture

Business services:

1. Identity Service
2. Vault Service
3. Security and Activity Service
4. Sharing Service
5. Notification Service

Platform components:

1. API Gateway
2. Message broker
3. Redis
4. Per-service MySQL databases
5. Centralized secrets and observability

Important design decisions:

- Do not create a separate Scheduler Service. Scheduled jobs stay in the service that owns the data.
- Do not create a separate Generator Service. Password generation is stateless and belongs in Security and Activity Service.
- Do not use Eureka or Spring Cloud Config if deploying to Kubernetes. Use Kubernetes-native service discovery and config.
- Do not split Vault, Security, and Sharing until the crypto and event boundaries are cleaned up.
- Preserve existing public API paths through the API Gateway so the Angular app does not need a full rewrite during migration.

---

## 2. Current System Reality

The current system is already logically modular, but it is not yet operationally separable.

### Backend domains already present

- Auth and identity
- User profile and settings
- Sessions and 2FA
- Vault entries, folders, categories, trash, snapshots
- Security audit, alerts, login attempts, rate limiting, captcha, duress mode
- Backup import and export
- Secure sharing
- Notifications and email
- Dashboard metrics and timeline analytics

### Frontend domains already present

- Landing and auth
- Dashboard
- Vault
- Backup
- Secure sharing
- User settings
- Notification polling

### Main coupling hotspots in the current monolith

1. Vault encryption depends on user-owned credential material.
2. Security analysis reads vault data directly.
3. Sharing reads vault data directly and performs crypto operations based on vault-owned secrets.
4. Password change re-encrypts all vault entries from user-facing flows.
5. Dashboard and timeline are cross-domain read models built from vault, security, auth, and sharing data.
6. The frontend expects stable monolith-style routes and a single base URL.

### Existing public API surface that should remain stable initially

- `/api/auth/**`
- `/api/users/**`
- `/api/settings/**`
- `/api/2fa/**`
- `/api/sessions/**`
- `/api/vault/**`
- `/api/categories/**`
- `/api/folders/**`
- `/api/security/**`
- `/api/dashboard/**`
- `/api/generator/**`
- `/api/timeline/**`
- `/api/shares/**`
- `/api/notifications/**`
- `/api/backup/**`

### Critical technical facts the migration must respect

- The backend is on Java 21, not Java 17.
- The current project already has Dockerfiles and Docker Compose.
- The frontend already assumes same-origin production routing.
- The generated OpenAPI client has drift and some endpoints are manually called using `HttpClient`.
- Hardcoded secrets currently exist and must be removed before any production migration work.

---

## 3. Migration Goals

### Primary goals

- Improve deployability and team ownership
- Reduce blast radius of changes
- Separate business domains by data ownership
- Preserve current user-facing behavior during migration
- Introduce reliable observability, secrets management, and CI/CD
- Keep local development simple

### Non-goals for the initial migration

- Rewriting the Angular application from scratch
- Changing the user-visible API paths immediately
- Moving to event sourcing
- Replacing MySQL everywhere
- Splitting every controller into its own microservice
- Introducing complex platform tools that the team cannot operate

---

## 4. Architecture Principles

The team should treat the following as hard rules.

### 4.1 Public API compatibility first

The API Gateway must preserve the existing external routes during migration. The frontend should continue to call the same paths while traffic is gradually rerouted behind the gateway.

### 4.2 Data ownership is the service boundary

Each service must own its tables, migrations, and write operations. No service may write to another service's database.

### 4.3 Synchronous calls for commands, asynchronous events for read models

Use synchronous HTTP only when immediate business confirmation is required. Use asynchronous events for:

- notifications
- dashboard aggregation
- activity timeline
- audit and alert fanout
- search/index/read models

### 4.4 Vault plaintext stays inside Vault ownership

Only Vault-owned code may decrypt stored credentials after the split. Other services must consume derived metadata or Vault-prepared payloads.

### 4.5 Migrate by strangler pattern, not by big bang

Extract one service at a time, keep the monolith functional, and reroute traffic incrementally through the gateway.

### 4.6 Local development must stay easy

Every phase must still be runnable by developers using Docker Compose and a single documented startup flow.

### 4.7 Observability is not optional

Every extracted service must have:

- health checks
- structured logs
- metrics
- distributed trace headers
- OpenAPI docs

---

## 5. Target Architecture

## 5.1 High-level service map

### API Gateway

Responsibilities:

- single frontend entry point
- request routing
- auth header forwarding
- rate limiting at the edge
- CORS
- request and trace correlation

Recommended public routes:

- preserve current `/api/...` routes exactly
- preserve `/share/:token` frontend route

### Identity Service

Owns:

- registration
- login
- refresh token
- logout
- user profile
- user settings
- security questions
- 2FA
- sessions
- account recovery
- duress password settings

Own tables:

- `users`
- `user_settings`
- `user_sessions`
- `two_factor_auth`
- `otp_tokens`
- `recovery_codes`
- `security_questions`

Public routes:

- `/api/auth/**`
- `/api/users/**`
- `/api/settings/**`
- `/api/2fa/**`
- `/api/sessions/**`

### Vault Service

Owns:

- vault entry CRUD
- folders
- categories
- trash
- snapshots and password history
- sensitive view flow
- backup export and import
- vault crypto

Own tables:

- `vault_entries`
- `folders`
- `categories`
- `vault_snapshots`
- `backup_exports`

Public routes:

- `/api/vault/**`
- `/api/categories/**`
- `/api/folders/**`
- `/api/backup/**`

Internal responsibilities:

- decrypt vault data
- compute password metadata at write time
- generate share-safe payloads for Sharing Service

### Security and Activity Service

Owns:

- audit logs
- security alerts
- login history
- password analysis
- security dashboard read models
- vault activity timeline read models
- password generation
- strength scoring

Own tables:

- `audit_logs`
- `security_alerts`
- `login_attempts`
- `password_analysis`
- `security_metrics_history`
- `activity_events`
- `dashboard_read_model`

Public routes:

- `/api/security/**`
- `/api/dashboard/**`
- `/api/generator/**`
- `/api/timeline/**`

Important rule:

- This service must not decrypt vault entries from the Vault database after extraction.
- It must consume domain events and derived metadata instead.

### Sharing Service

Owns:

- secure share creation
- token lifecycle
- view counting
- expiration
- share revocation

Own tables:

- `secure_shares`

Public routes:

- `/api/shares/**`

Important rule:

- Sharing Service does not read vault tables directly.
- It requests a share-safe payload from Vault Service using an internal API.

### Notification Service

Owns:

- in-app notifications
- email delivery
- notification fanout

Own tables:

- `notifications`

Public routes:

- `/api/notifications/**`

Important rule:

- Notification Service consumes events from all other services.
- It should not become a general-purpose business orchestrator.

---

## 5.2 Platform components

### Message broker

Recommended:

- RabbitMQ for simplicity and fast team adoption

Use cases:

- notification fanout
- audit event fanout
- dashboard and timeline read models
- share expiration and cleanup events
- account deletion and lifecycle events

### Redis

Use for:

- gateway rate limiting
- short-lived session or unlock state if needed
- transient replay protection
- idempotency keys

### Databases

Use one MySQL database per service. This is easiest for the current team because it stays aligned with the existing stack.

### Secrets management

Use one of:

- AWS Secrets Manager in cloud
- External Secrets Operator on Kubernetes
- `.env` files for local development only

### Observability

Minimum stack:

- OpenTelemetry
- Prometheus
- Grafana
- centralized logs

Recommended:

- Loki for logs if the team wants lower operational cost than ELK

---

## 6. Public Route Preservation Plan

The external API contract should not change during the migration. The Gateway will route existing paths to the correct backend service.

| Existing route | Target owner |
|---|---|
| `/api/auth/**` | Identity Service |
| `/api/users/**` | Identity Service |
| `/api/settings/**` | Identity Service |
| `/api/2fa/**` | Identity Service |
| `/api/sessions/**` | Identity Service |
| `/api/vault/**` | Vault Service |
| `/api/categories/**` | Vault Service |
| `/api/folders/**` | Vault Service |
| `/api/backup/**` | Vault Service |
| `/api/security/**` | Security and Activity Service |
| `/api/dashboard/**` | Security and Activity Service |
| `/api/generator/**` | Security and Activity Service |
| `/api/timeline/**` | Security and Activity Service |
| `/api/shares/**` | Sharing Service |
| `/api/notifications/**` | Notification Service |

This avoids a large Angular rewrite and lets the frontend move gradually.

---

## 7. Crypto and Data Boundary Strategy

This is the most important section in the entire migration.

### 7.1 Current problem

Today, multiple modules derive encryption context from user-owned data and then directly decrypt vault records. That works inside a monolith and becomes dangerous and awkward in microservices.

### 7.2 Target rule

After the Vault Service is extracted:

- only Vault Service may decrypt stored vault credentials
- Security and Activity Service receives derived metadata only
- Sharing Service receives a Vault-prepared share payload only
- Notification Service never touches secrets

### 7.3 Required refactor before Vault extraction

Introduce a `VaultCryptoFacade` inside the monolith and route all vault crypto through it.

The facade must become the only code path for:

- encrypting usernames, passwords, and notes
- decrypting vault entry fields
- sensitive view flows
- backup export and import crypto
- share preparation
- password change re-encryption

### 7.4 Required metadata generated by Vault at write time

Whenever a vault password is created or changed, Vault code should compute and publish:

- strength score
- strength label
- password last rotated timestamp
- sensitivity flag
- category and folder references
- password fingerprint for reuse detection

### 7.5 Password fingerprint design

To let Security and Activity Service detect reused passwords without seeing plaintext:

- compute a deterministic password fingerprint inside Vault
- use a keyed HMAC such as `HMAC-SHA256(password, security-pepper)`
- never publish the plaintext password
- never publish the raw vault encryption key

The Security and Activity Service can use this fingerprint to detect duplicates safely enough for product analytics.

### 7.6 Share payload design

When Sharing Service needs to create a share:

1. Sharing receives the create request
2. Sharing calls an internal Vault API
3. Vault validates access to the entry
4. Vault decrypts the secret
5. Vault re-encrypts it into a share-safe payload
6. Vault returns only:
   - entry title
   - website URL
   - encrypted share blob
   - IV
   - share metadata
7. Sharing stores and manages token lifecycle

This keeps plaintext and vault crypto inside Vault ownership.

---

## 8. Event Model

Use an outbox pattern from day one of extraction.

### 8.1 Why outbox

Outbox prevents lost events when a database write succeeds but message publishing fails.

### 8.2 Event publishing rules

- Each service writes business data and outbox data in the same transaction.
- A background publisher relays outbox events to RabbitMQ.
- Consumers must be idempotent.

### 8.3 Initial event catalog

Identity events:

- `UserRegistered`
- `UserLoggedIn`
- `UserLoginFailed`
- `UserLocked`
- `UserLoggedOut`
- `UserProfileUpdated`
- `UserSettingsUpdated`
- `TwoFactorEnabled`
- `TwoFactorDisabled`
- `PasswordChanged`
- `AccountDeletionScheduled`
- `AccountDeletionCanceled`
- `AccountDeleted`

Vault events:

- `VaultEntryCreated`
- `VaultEntryUpdated`
- `VaultEntryDeleted`
- `VaultEntryRestored`
- `VaultTrashEmptied`
- `VaultSnapshotCreated`
- `VaultPasswordViewed`
- `VaultExported`
- `VaultImported`
- `VaultPasswordMetadataUpdated`

Sharing events:

- `ShareCreated`
- `ShareAccessed`
- `ShareRevoked`
- `ShareExpired`

Security events:

- `SecurityAlertCreated`
- `SecurityAlertRead`
- `SecurityAuditGenerated`

Notification events:

- `NotificationCreated`
- `NotificationRead`
- `NotificationDeleted`
- `EmailDeliveryRequested`

---

## 9. Frontend Migration Strategy

The Angular app should not be rewritten. It should be stabilized and moved behind the gateway.

### 9.1 Keep these assumptions stable at first

- same public routes
- same response shapes where possible
- same JWT header semantics
- same share-link route pattern

### 9.2 Frontend work required before extraction

1. Make the generated OpenAPI spec authoritative.
2. Regenerate the Angular client from the correct backend contract.
3. Remove stale generated services that do not match the real backend.
4. Replace manual workarounds only after the API spec is fixed.

### 9.3 Frontend work required during extraction

- Point `apiBaseUrl` to the gateway only.
- Keep the Angular router unchanged.
- Regenerate clients per extraction milestone.
- Add a single `ApiGatewayHealthService` for startup diagnostics.
- Move token parsing and storage into one dedicated auth state service.

### 9.4 Frontend work required after extraction

- Consider moving refresh token storage from `localStorage` to HttpOnly cookies
- standardize error envelopes
- standardize loading and retry behavior
- standardize feature-level observability

---

## 10. Delivery Phases

This is the recommended implementation sequence.

## Phase 0: Stabilize the Monolith

Duration: 1 to 2 weeks

Objective:

- create a safe baseline before extraction

Tasks:

- remove hardcoded secrets from application properties
- replace `spring.jpa.hibernate.ddl-auto=update` with Flyway or Liquibase migrations
- define the authoritative OpenAPI contract
- remove or flag stale generated frontend APIs
- add a service boundary decision record
- create a route inventory and table ownership inventory
- add baseline integration tests for current critical flows

Critical flows to lock down:

- register and verify email
- login and refresh token
- 2FA setup and verify
- create, update, view, delete, restore vault entry
- sensitive entry unlock
- share create and share access
- backup export and import
- notifications polling
- dashboard load

Exit criteria:

- no hardcoded production secrets
- migration tool added and working
- route inventory approved
- baseline tests passing in CI

## Phase 1: Harden Internal Boundaries in the Monolith

Duration: 2 weeks

Objective:

- make extraction possible without changing deployment yet

Tasks:

- introduce internal facades:
  - `IdentityFacade`
  - `VaultFacade`
  - `SecurityFacade`
  - `SharingFacade`
  - `NotificationFacade`
- forbid direct cross-domain repository access outside owning modules
- introduce `VaultCryptoFacade`
- add outbox tables and outbox publisher
- generate password metadata and fingerprint in vault write flows
- refactor dashboard and timeline logic toward event consumption

Exit criteria:

- all crypto flows go through one facade
- cross-domain DB access is reduced to approved adapters only
- outbox is used for new domain events

## Phase 2: Build the Platform Foundation

Duration: 2 weeks

Objective:

- prepare the runtime environment for gradual extraction

Tasks:

- add API Gateway project
- add shared service template
- add shared tracing and logging setup
- add local Docker Compose for:
  - gateway
  - RabbitMQ
  - Redis
  - per-service MySQL instances
- add CI templates for backend services
- add image build and scan steps
- add secret loading from environment

Recommended stack:

- Spring Boot 3.2.x
- Java 21
- Spring Cloud Gateway
- RabbitMQ
- Redis
- MySQL
- OpenTelemetry
- Prometheus and Grafana

Exit criteria:

- gateway runs locally
- all supporting infra runs in Docker Compose
- service template can start, expose health, and publish metrics

## Phase 3: Extract Notification Service First

Duration: 1 to 2 weeks

Objective:

- extract the lowest-risk domain first

Why first:

- clear table ownership
- mostly event-driven
- minimal crypto concerns
- fast operational learning

Tasks:

- move notification controller and service
- move `notifications` table into Notification DB
- consume events from monolith through RabbitMQ
- expose `/api/notifications/**` through gateway
- keep email delivery in Notification Service

Exit criteria:

- notification polling works through gateway
- in-app notifications still update correctly
- email events are delivered asynchronously

## Phase 4: Extract Identity Service

Duration: 3 weeks

Objective:

- isolate auth, user, settings, sessions, and 2FA

Tasks:

- move identity-related tables
- move JWT issuance and refresh flows
- move user profile and settings
- move sessions and 2FA flows
- move account recovery and security questions
- publish domain events for:
  - login success
  - login failure
  - profile changes
  - password changes
  - account lifecycle

Important implementation rule:

- Vault Service must not depend on Identity DB directly after this phase

What Vault will still need:

- authenticated user identity from JWT
- specific user preference projections if necessary

Exit criteria:

- login, logout, refresh token, profile, settings, sessions, and 2FA all work through the gateway
- frontend needs only gateway URL changes, not route changes

## Phase 5: Finish the Crypto Boundary Refactor

Duration: 2 weeks

Objective:

- remove the last blockers before Vault extraction

Tasks:

- ensure all password analysis inputs are emitted by Vault events
- ensure all share creation crypto can be delegated to Vault internal APIs
- ensure password change re-encryption remains a Vault-owned workflow
- ensure backup export and import remain Vault-owned workflows
- build internal API contracts:
  - `POST /internal/vault/share-source`
  - `POST /internal/vault/security-metadata`
  - `POST /internal/vault/reprocess-metadata`

Exit criteria:

- Security logic no longer requires direct vault decryption outside Vault code
- Sharing logic no longer requires direct vault table access

## Phase 6: Extract Vault Service

Duration: 3 to 4 weeks

Objective:

- isolate encrypted vault operations and vault-owned data

Tasks:

- move vault tables into Vault DB
- move vault controllers and services
- move category and folder ownership
- move trash and snapshot flows
- move backup export and import
- expose routes through gateway
- publish Vault domain events

Internal APIs required:

- share payload preparation
- metadata backfill for Security Service

Exit criteria:

- vault CRUD works through gateway
- categories and folders work through gateway
- trash and snapshots work through gateway
- backup export and import work through gateway
- Vault DB is no longer written by any other service

## Phase 7: Extract Sharing Service

Duration: 2 weeks

Objective:

- isolate secure link lifecycle from vault data ownership

Tasks:

- move share table and share controller
- integrate with Vault internal share-source API
- keep public route `/api/shares/**`
- keep public unauthenticated token access
- move share cleanup scheduler into Sharing Service

Exit criteria:

- create share works through gateway
- public share access still works
- revocation and expiration still work

## Phase 8: Extract Security and Activity Service

Duration: 3 weeks

Objective:

- isolate reporting, audit, alerts, and security analytics

Tasks:

- move audit logs
- move security alerts
- move login attempt history
- move password analysis
- move dashboard read models
- move timeline read models
- move password generator endpoints
- build event consumers for Identity, Vault, and Sharing events

Important design rule:

- this service consumes metadata and events
- it must not read Vault DB directly

Exit criteria:

- dashboard still loads
- security alerts still work
- audit logs and login history still work
- generator still works
- timeline works from event-fed read models

## Phase 9: Retire the Monolith and Prepare Kubernetes Deployment

Duration: 2 to 3 weeks

Objective:

- remove the remaining monolith responsibilities and productionize the platform

Tasks:

- cut over any leftover routes to extracted services
- archive or remove obsolete monolith modules
- add Kubernetes manifests or Helm charts
- add HPA
- add pod disruption budgets
- add backup and restore validation
- add disaster recovery documentation

Recommended production order:

1. Docker Compose for local development
2. CI deployment to a shared test environment
3. production-like environment
4. Kubernetes only after the service boundaries are stable

Exit criteria:

- no business traffic hits the old monolith
- all public API routes are gateway-backed
- rollout and rollback procedures are documented

---

## 11. Suggested Repository Structure

Recommended repository structure after extraction:

```text
/
  frontend/
  gateway/
  services/
    identity-service/
    vault-service/
    security-activity-service/
    sharing-service/
    notification-service/
  platform/
    docker/
    compose/
    scripts/
    observability/
  deploy/
    kubernetes/
    helm/
  docs/
  plans/
```

If the team prefers a monorepo, keep it as a monorepo until the migration is stable. Do not split into many repositories too early.

---

## 12. Database Migration Strategy

### 12.1 Tooling

Use Flyway or Liquibase for every service.

### 12.2 General rules

- one migration history per service database
- no `ddl-auto=update` in shared or production environments
- every extraction phase must have reversible migration scripts where feasible

### 12.3 Data migration order

1. Notification data
2. Identity data
3. Vault data
4. Sharing data
5. Security and activity data

### 12.4 Cutover pattern per service

1. Create service DB schema
2. Backfill data from monolith DB
3. Run dual-write only if absolutely necessary and for a short period
4. Validate reads
5. Cut traffic via gateway
6. Disable monolith writes
7. Remove old code path

### 12.5 Preferred rule on dual-write

Avoid dual-write if possible. Prefer:

- backfill
- brief maintenance window
- route cutover

Dual-write should be a last resort because it creates reconciliation problems.

---

## 13. CI/CD Plan

Every service should use the same delivery contract.

### 13.1 Build pipeline per service

- compile
- unit tests
- integration tests
- static analysis
- image build
- image scan
- OpenAPI validation
- deployment to test

### 13.2 Required deployment gates

- health check passes
- readiness check passes
- migration applied
- smoke tests pass

### 13.3 Recommended environments

- local
- shared-dev
- integration
- staging
- production

### 13.4 Release strategy

Use rolling or blue-green deployment via gateway routing. Avoid big-bang full-stack cutovers.

---

## 14. Testing Strategy

This migration fails if testing is weak. Testing must increase before service count increases.

### 14.1 Test layers

Monolith baseline:

- controller tests
- service tests
- repository tests
- end-to-end flows

Service extraction:

- unit tests
- contract tests
- integration tests per service
- consumer-driven contract tests for gateway and frontend
- event consumer idempotency tests

### 14.2 Minimum smoke suite after each extraction

- login
- refresh token
- dashboard load
- vault list load
- create vault entry
- sensitive view
- create share
- open share
- notification unread count
- export vault

### 14.3 Performance and resilience tests

Add targeted tests for:

- login bursts
- vault search latency
- dashboard load under event lag
- notification backlog
- share token expiry and cleanup

---

## 15. Security Requirements During Migration

These are mandatory.

### 15.1 Secrets

- no credentials in source control
- environment-specific secret stores only
- rotate JWT secret during controlled window if current secret has been exposed

### 15.2 Service-to-service communication

- internal service auth between gateway and services
- signed JWT validation in each service
- short-lived internal tokens where required

### 15.3 Data protection

- only Vault may decrypt vault contents
- all sensitive logs must be redacted
- audit fields must remain intact across migrations

### 15.4 Compliance hygiene

- maintain traceability for sensitive actions
- log who did what, when, and from where
- preserve account deletion and security alert behaviors

---

## 16. Operational Runbooks Required

Before production cutover, create runbooks for:

- service startup failure
- database migration rollback
- stuck outbox messages
- RabbitMQ outage
- Redis outage
- gateway routing rollback
- invalid JWT secret or signing issues
- notification delivery failure
- share token abuse or replay concerns
- password-change re-encryption failure

---

## 17. Risk Register

| Risk | Why it matters | Mitigation |
|---|---|---|
| Crypto boundary split is done too early | can break vault, sharing, backup, and security flows | complete `VaultCryptoFacade` and metadata/event refactor before Vault extraction |
| Frontend contract drift continues | client regeneration and integration become unreliable | freeze authoritative OpenAPI per phase and regenerate clients from it |
| Too many services too early | team slows down and debugging gets harder | follow the phase order exactly |
| Dual-write causes inconsistent data | hidden data corruption risk | prefer cutover windows and outbox pattern |
| Timeline and dashboard become inaccurate | cross-domain reporting depends on events | build read models from tested event contracts |
| Hardcoded secrets remain | production risk | remove in Phase 0 and block release until verified |
| Kubernetes is introduced too early | operational complexity before value | stabilize in Compose and shared-dev first |

---

## 18. Definition of Done Per Extracted Service

A service is considered complete only when all of the following are true:

- routes are served through the gateway
- service owns its database
- migrations are versioned
- OpenAPI spec is published
- health checks exist
- metrics exist
- logs are structured
- alerts exist
- smoke tests pass
- rollback is documented
- no other service writes its tables

---

## 19. First 30 Days Checklist

This is the recommended immediate execution checklist.

### Week 1

- remove hardcoded secrets
- add Flyway or Liquibase
- create route inventory
- create table ownership inventory
- define target service boundaries

### Week 2

- stabilize OpenAPI spec
- regenerate Angular client
- add baseline smoke tests
- add outbox infrastructure in monolith

### Week 3

- introduce `VaultCryptoFacade`
- add metadata generation and password fingerprinting
- add event contracts
- build local Docker Compose platform stack

### Week 4

- extract Notification Service
- route `/api/notifications/**` through gateway
- validate notification polling and email delivery

---

## 20. Final Recommendation

If the team wants the highest probability of success, use this migration sequence:

1. Stabilize monolith
2. Harden internal boundaries
3. Build gateway and platform foundation
4. Extract Notification Service
5. Extract Identity Service
6. Finish crypto boundary refactor
7. Extract Vault Service
8. Extract Sharing Service
9. Extract Security and Activity Service
10. Retire monolith and productionize

This order is slower than a slide-deck plan and much faster than a failed migration.

