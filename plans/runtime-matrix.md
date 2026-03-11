# Runtime Configuration Matrix

## Backend Runtime
| Component | Version | Notes |
|-----------|---------|-------|
| Java | 21 | Eclipse Temurin |
| Maven | 3.9 | For builds |
| Spring Boot | 3.2.3 | Framework |
| Base Image | eclipse-temurin:21-jre-alpine | Production runtime |

## Frontend Runtime
| Component | Version | Notes |
|-----------|---------|-------|
| Node.js | 20.x | LTS recommended |
| Angular | 18.2.0 | Frontend framework |
| npm | 10.x | Package manager |

## Database
| Component | Version | Notes |
|-----------|---------|-------|
| MySQL | 8.0+ | Production |
| H2 | 2.x | Testing only |

## Build Tools
| Component | Version | Notes |
|-----------|---------|-------|
| JDK | 21 | For compilation |
| Angular CLI | 18.2.21 | For frontend builds |

## Configuration Profiles
| Profile | Use Case | Config Source |
|---------|----------|---------------|
| default | Local development | application.properties |
| dev | Development | application-dev.properties |
| docker | Docker Compose | application-docker.properties |
| prod | AWS/Production | application-prod.properties + Secrets Manager |

## Environment Variables Required
| Variable | Description | Required |
|----------|-------------|----------|
| SPRING_DATASOURCE_URL | Database connection URL | Yes |
| SPRING_DATASOURCE_USERNAME | Database username | Yes |
| SPRING_DATASOURCE_PASSWORD | Database password | Yes |
| JWT_SECRET | JWT signing secret (min 256 bits) | Yes |
| SPRING_MAIL_USERNAME | Email username | Yes |
| SPRING_MAIL_PASSWORD | Email password/App password | Yes |
| AI_OPENAI_API_KEY | OpenAI API key | Optional |
