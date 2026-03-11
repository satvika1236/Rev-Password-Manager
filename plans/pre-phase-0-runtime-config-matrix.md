# Pre-Phase 0 Runtime And Config Matrix

Date: 2026-03-07

## Runtime decision

The backend stays on Java 21 for Pre-Phase 0.

Reason:
- `pom.xml` already targets Java 21.
- The backend Docker image already uses Temurin 21.
- Dropping to Java 17 would add churn without reducing current migration risk.

If the evaluator later requires Java 17, make that downgrade as a dedicated follow-up before Phase 1 starts.

## Runtime matrix

| Surface | Version | Source of truth | Notes |
|---|---|---|---|
| Backend JDK | 21 | `pom.xml` | Maven compiler uses `${java.version}` via `maven.compiler.release`. |
| Backend Docker JRE | 21 | `Dockerfile` | Build and runtime stages share `JAVA_VERSION`. |
| Maven | 3.9+ | `README.md` | Matches the container build image family. |
| Frontend Node.js | 20.x | `frontend/.nvmrc`, `frontend/package.json`, `frontend/Dockerfile` | Local and Docker builds align on Node 20. |
| Frontend npm | 10.x | `frontend/package.json` | Expected with Node 20. |
| MySQL | 8.0 | `docker-compose.yml`, `README.md` | Shared local and container baseline. |

## Config profile matrix

| Profile | Purpose | Activation | Config source | Notes |
|---|---|---|---|---|
| `local` | Manual developer runs | default profile or `SPRING_PROFILES_ACTIVE=local` | `.env` via `spring.config.import`, shell env vars | Uses localhost MySQL defaults and local logging paths. |
| `docker` | `docker compose` runs | `SPRING_PROFILES_ACTIVE=docker` | Compose environment variables | Uses container service hostnames and mounted paths. |
| `aws` | Cloud deployment baseline | `SPRING_PROFILES_ACTIVE=aws` | Environment variables / secret manager injection | Uses externally supplied datasource values and stricter defaults. |

## Secret handling rules

- Never store real database, JWT, or SMTP credentials in tracked Spring property files.
- Keep `.env` local-only; the repository only keeps `.env.example`.
- Treat log files, coverage output, Sonar output, and build output as generated artifacts, not source files.
