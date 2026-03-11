# Project Title: End-to-End Modernization of Password Manager Monolithic Secure Vault to Cloud-Native Microservices

## Overview

Password Manager serves as a full-stack monolithic secure password management web application that allows users to safely store and organize credentials for all online accounts. Users create accounts with a strong master password and security questions, login securely, manage an encrypted vault, generate complex random passwords with customizable rules, search/filter/sort entries, mark favorites, perform strength audits, enable 2FA, export/import encrypted backups, and receive security alerts for weak or reused passwords. The application emphasizes enterprise-grade security through AES encryption, master-password protection, simulated 2FA, verification codes, and comprehensive audit reporting, delivered via an intuitive responsive web interface.

This project modernizes the existing monolithic application (Spring Boot backend + Angular frontend + MySQL) into a secure, scalable, and production-ready cloud-native microservices system.

---

## Transformation Phases

The transformation executes in two phases:
- **Phase 1:** Containerization with CI/CD-enabled AWS deployment
- **Phase 2:** Full microservices refactoring and local Kubernetes orchestration

---

## Phase 1: Containerization, CI/CD & AWS Deployment

### 1.1 Objectives

- Dockerize the Spring Boot backend and Angular frontend using multi-stage builds
- Deploy the backend on AWS EC2 Auto Scaling Groups behind an Application Load Balancer
- Migrate the database to highly available AWS RDS MySQL with Multi-AZ configuration
- Implement centralized secrets management using AWS Secrets Manager
- Design and operate a complete CI/CD pipeline with Jenkins

### 1.2 Docker Implementation

#### Backend Dockerfile (Multi-stage Build)

```dockerfile
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

#### Frontend Dockerfile (Multi-stage Build)

```dockerfile
# Stage 1: Build
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build --configuration=production

# Stage 2: Nginx
FROM nginx:alpine
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 1.3 AWS Infrastructure Setup

#### RDS MySQL Multi-AZ Deployment

```terraform
# terraform/main.tf
resource "aws_db_instance" "password_manager" {
  identifier           = "password-manager-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.medium"
  allocated_storage    = 50
  storage_encrypted    = true
  multi_az             = true
  username             = var.db_username
  password             = var.db_password
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name = aws_db_subnet_group.main.name
  backup_retention_period = 7
  skip_final_snapshot  = true
}
```

#### EC2 Auto Scaling Group

```terraform
# terraform/asg.tf
resource "aws_launch_template" "backend" {
  name_prefix   = "password-manager-backend"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  key_name      = var.key_pair
  
  security_group_ids = [aws_security_group.backend.id]
  
  user_data = base64encode(<<-EOF
              #!/bin/bash
              docker run -d --name password-manager \
                -p 8080:8080 \
                -e SPRING_DATASOURCE_URL=${var.db_endpoint} \
                -e JWT_SECRET=${var.jwt_secret} \
                ${aws_ecr_repository.backend.repository_url}:latest
              EOF
  )
}

resource "aws_autoscaling_group" "backend" {
  name                = "password-manager-asg"
  vpc_zone_identifier = [aws_subnet.private.*.id]
  desired_capacity    = 2
  min_size            = 2
  max_size            = 5
  target_group_arns   = [aws_lb_target_group.backend.arn]
  
  launch_template {
    id      = aws_launch_template.backend.id
    version = "$Latest"
  }
}
```

#### Application Load Balancer

```terraform
# terraform/alb.tf
resource "aws_lb" "main" {
  name               = "password-manager-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.*.id]
}

resource "aws_lb_target_group" "backend" {
  name     = "password-manager-backend-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  health_check {
    path                = "/actuator/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "frontend" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}
```

### 1.4 AWS Secrets Manager Integration

```java
// Spring Boot configuration
@Configuration
public class AwsSecretsManagerConfig {
    
    @Value("${aws.secretsmanager.secret-name}")
    private String secretName;
    
    @Bean
    public AWSSecretsManager awsSecretsManager() {
        return AWSSecretsManagerBuilder.defaultClient();
    }
    
    @Bean
    public SecretDto getSecret() {
        GetSecretValueResult result = awsSecretsManager()
            .getSecretValue(new GetSecretValueRequest()
                .withSecretId(secretName));
        return new ObjectMapper().readValue(result.getSecretString(), SecretDto.class);
    }
}
```

```yaml
# application.yml
spring:
  config:
    import: optional:aws-secretsmanager:${SECRET_NAME}
```

### 1.5 Jenkins CI/CD Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        AWS_ACCOUNT_ID = credentials('aws-account-id')
        ECR_REPOSITORY = 'password-manager'
        DOCKER_IMAGE = "${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/${ECR_REPOSITORY}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests=false'
            }
        }
        
        stage('Test') {
            steps {
                sh 'mvn test'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'mvn sonar:sonar'
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                sh """
                    docker build -t ${DOCKER_IMAGE}:${BUILD_NUMBER} .
                    docker build -t ${DOCKER_IMAGE}:latest .
                """
            }
        }
        
        stage('Push to ECR') {
            steps {
                sh """
                    aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com
                    docker push ${DOCKER_IMAGE}:${BUILD_NUMBER}
                    docker push ${DOCKER_IMAGE}:latest
                """
            }
        }
        
        stage('Deploy to AWS') {
            steps {
                script {
                    def ami = sh(script: "aws ec2 describe-instances --filters 'Name=tag:Name,Values=password-manager' --query 'Reservations[0].Instances[0].ImageId' --output text", returnStdout: true).trim()
                    
                    sh """
                        aws autoscaling update-auto-scaling-group \
                            --auto-scaling-group-name password-manager-asg \
                            --min-size 2 --max-size 5 --desired-capacity 2
                    """
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
```

### 1.6 Phase 1 Checklist

- [ ] Create Dockerfiles for backend (multi-stage) and frontend (multi-stage)
- [ ] Set up AWS VPC with public/private subnets
- [ ] Configure RDS MySQL with Multi-AZ
- [ ] Create EC2 Auto Scaling Group
- [ ] Set up Application Load Balancer
- [ ] Configure AWS Secrets Manager
- [ ] Integrate Spring Cloud AWS
- [ ] Create Jenkins pipeline
- [ ] Configure ECR repository
- [ ] Test CI/CD pipeline end-to-end

---

## Phase 2: Microservices Transformation & Kubernetes Orchestration

### 2.1 Backend Components Analysis

#### Current Backend Components (15 Controllers)

| # | Controller | Current Service Assignment | Services |
|---|------------|---------------------------|----------|
| 1 | AuthController | User Service | Authentication, Registration |
| 2 | BackupController | Security Service | Export, Import |
| 3 | CategoryController | Vault Service | Category management |
| 4 | DashboardController | Security Service | Security metrics |
| 5 | FolderController | Vault Service | Folder management |
| 6 | NotificationController | Notification Service | Notifications |
| 7 | PasswordGeneratorController | Generator Service | Password generation |
| 8 | SecureShareController | **MISSING** | Sharing |
| 9 | SecurityController | Security Service | Security features |
| 10 | SessionController | **MISSING** | Session management |
| 11 | TwoFactorController | User Service | 2FA |
| 12 | UserController | User Service | User management |
| 13 | UserSettingsController | User Service | Settings |
| 14 | VaultController | Vault Service | Vault CRUD |
| 15 | VaultTimelineController | Vault Service | Timeline |

#### Additional Backend Components

- **Security Components:** EncryptionService, RateLimitService, CaptchaService, MasterPasswordValidator
- **Schedulers:** AccountDeletionScheduler, SecureShareCleanupScheduler, TrashCleanupScheduler
- **Email:** EmailService
- **Sharing:** SecureShareService, ShareEncryptionService, ShareExpirationService

### 2.2 Revised Domain-Driven Service Decomposition

Refactor the monolith into **7 domain-driven microservices**:

#### User Service
- Authentication and login/logout
- Master password management
- Profile updates
- 2FA setup (TOTP)
- Security questions management
- Account recovery
- **Session management** ← Added (SessionController)
- User settings

#### Vault Service
- Encrypted credential storage
- CRUD operations for password entries
- Search, filter, sort functionality
- Favorites management
- Category management
- Folder hierarchy
- Secure re-authentication for viewing passwords
- Vault timeline and activity tracking
- Trash management

#### Generator Service
- Customizable strong password generation
  - Length configuration
  - Character sets (uppercase, lowercase, numbers, symbols)
  - Exclusion rules
- Password strength indicator
- Clipboard copy functionality
- Direct save to vault

#### Security Service
- Password strength analysis
- Weak password detection
- Reused password detection
- Audit reports
- **Export/import encrypted backups** ← BackupController
- Verification code handling
- **Security alerts**
- **Encryption services**
- **Rate limiting**
- **Captcha verification**

#### Notification Service
- Real-time security alerts
- Breach warnings
- In-app notifications for sensitive actions
- Email notifications (via EmailService)

#### Sharing Service ← NEW SERVICE
- Secure password sharing
- Link generation with permissions
- Share token management
- Expiration handling
- Access validation

#### Scheduler Service ← NEW SERVICE (or split across services)
- Account deletion scheduling
- Trash cleanup automation
- Share expiration cleanup

### 2.3 Complete Microservices Architecture

```mermaid
flow TB
    subgraph Client["Angular Frontend"]
        UI["SPA"]
    end
    
    subgraph AWS["AWS Cloud"]
        ALB["Application Load Balancer"]
        
        subgraph K8s["Kubernetes Cluster (Minikube)"]
            Gateway["API Gateway<br/>Rate Limiting<br/>Circuit Breaker"]
            
            subgraph Services["7 Microservices"]
                User["User Service<br/>:8081<br/>Auth+Profile+2FA+Session"]
                Vault["Vault Service<br/>:8082<br/>Entries+Categories+Folders"]
                Generator["Generator Service<br/>:8083<br/>Password Generation"]
                Security["Security Service<br/>:8084<br/>Audit+Breach+Backup"]
                Notify["Notification Service<br/>:8085<br/>Alerts+Email"]
                Share["Sharing Service<br/>:8086<br/>Secure Sharing"]
                Scheduler["Scheduler Service<br/>:8087<br/>Cleanup Tasks"]
            end
            
            subgraph Infrastructure["Infrastructure"]
                Eureka["Eureka Server<br/>:8761"]
                Config["Config Server<br/>:8888"]
            end
            
            subgraph Data["Databases (Per Service)"]
                UserDB[("User DB<br/>MySQL")]
                VaultDB[("Vault DB<br/>MySQL")]
                GenDB[("Generator DB<br/>MySQL")]
                SecDB[("Security DB<br/>MySQL")]
                NotifyDB[("Notification DB<br/>MySQL")]
                ShareDB[("Sharing DB<br/>MySQL")]
                SchedDB[("Scheduler DB<br/>MySQL")]
            end
        end
    end
    
    UI --> ALB
    ALB --> Gateway
    Gateway --> User
    Gateway --> Vault
    Gateway --> Generator
    Gateway --> Security
    Gateway --> Notify
    Gateway --> Share
    Gateway --> Scheduler
    
    User --> UserDB
    Vault --> VaultDB
    Generator --> GenDB
    Security --> SecDB
    Notify --> NotifyDB
    Share --> ShareDB
    Scheduler --> SchedDB
    
    User --> Eureka
    Vault --> Eureka
    Generator --> Eureka
    Security --> Eureka
    Notify --> Eureka
    Share --> Eureka
    Scheduler --> Eureka
```

### 2.4 Service Responsibilities Detail

#### User Service - `/api/auth/**`, `/api/users/**`, `/api/2fa/**`, `/api/sessions/**`
- Authentication (login, register, logout)
- Master password management
- Two-factor authentication (TOTP, backup codes)
- Security questions (setup, verification)
- Account recovery
- Profile management
- Session management (view, revoke sessions)
- User settings

**Controllers:** AuthController, TwoFactorController, UserController, UserSettingsController, SessionController
**Entities:** User, UserSession, UserSettings, TwoFactorAuth, OtpToken, RecoveryCode, SecurityQuestion
**Services:** AuthenticationService, RegistrationService, TwoFactorService, SessionService, AccountRecoveryService, SecurityQuestionService, UserService, UserSettingsService

#### Vault Service - `/api/vault/**`
- Vault entry CRUD
- Category management
- Folder hierarchy
- Favorites
- Search, filter, sort
- Secure password viewing (re-auth)
- Timeline tracking
- Trash management

**Controllers:** VaultController, CategoryController, FolderController, VaultTimelineController
**Entities:** VaultEntry, Category, Folder, VaultSnapshot
**Services:** VaultService, VaultTrashService, CategoryService, FolderService

#### Generator Service - `/api/password-generator/**`
- Password generation with rules
- Strength calculation
- Clipboard operations

**Controllers:** PasswordGeneratorController
**Services:** PasswordGeneratorService

#### Security Service - `/api/security/**`, `/api/dashboard/**`, `/api/backup/**`
- Password strength analysis
- Weak/reused password detection
- Breach monitoring (HaveIBeenPwned)
- Audit logging
- Security alerts
- Backup export/import
- Encryption services
- Rate limiting
- Captcha verification
- Duress password

**Controllers:** SecurityController, DashboardController, BackupController
**Entities:** AuditLog, SecurityAlert, LoginAttempt, PasswordAnalysis
**Services:** SecurityAuditService, SecurityAlertService, PasswordStrengthService, EncryptionService, RateLimitService, CaptchaService, ExportService, ImportService

#### Notification Service - `/api/notifications/**`
- In-app notifications
- Security alerts delivery
- Breach warnings
- Email notifications (EmailService)

**Controllers:** NotificationController
**Entities:** Notification
**Services:** NotificationService, EmailService

#### Sharing Service - `/api/share/**`
- Create share links
- Permission management
- Token generation
- Expiration handling
- Access validation

**Controllers:** SecureShareController
**Entities:** SecureShare, ShareToken, SharePermission
**Services:** SecureShareService, ShareEncryptionService, ShareExpirationService, ShareTokenGenerator

#### Scheduler Service (Background Tasks)
- Account deletion scheduling
- Trash cleanup
- Share expiration cleanup

**Services:** AccountDeletionService, TrashCleanupScheduler, SecureShareCleanupScheduler

### 2.5 Phase 2 Checklist (Updated)

- [ ] Design domain-driven bounded contexts (7 services)
- [ ] Create 7 microservices projects
- [ ] Set up Eureka Server
- [ ] Set up Config Server
- [ ] Implement API Gateway with routing
- [ ] Implement circuit breaker patterns
- [ ] Create Kubernetes deployments
- [ ] Create Kubernetes services
- [ ] Configure Kubernetes secrets
- [ ] Configure ConfigMaps
- [ ] Set up Horizontal Pod Autoscaler
- [ ] Configure Ingress
- [ ] Deploy ELK Stack
- [ ] Deploy Prometheus + Grafana
- [ ] Deploy Jaeger for tracing
- [ ] Test inter-service communication
- [ ] Verify Kubernetes orchestration

### 2.2 Microservices Architecture

```mermaid
flow TB
    subgraph Client["Angular Frontend"]
        UI["SPA"]
    end
    
    subgraph AWS["AWS Cloud"]
        ALB["Application Load Balancer"]
        
        subgraph K8s["Kubernetes Cluster (Minikube)"]
            Gateway["API Gateway<br/>Rate Limiting<br/>Circuit Breaker"]
            
            subgraph Services["Microservices"]
                User["User Service<br/>:8081"]
                Vault["Vault Service<br/>:8082"]
                Generator["Generator Service<br/>:8083"]
                Security["Security Service<br/>:8084"]
                Notify["Notification Service<br/>:8085"]
            end
            
            subgraph Infrastructure["Infrastructure"]
                Eureka["Eureka Server<br/>:8761"]
                Config["Config Server<br/>:8888"]
            end
            
            subgraph Data["Databases"]
                UserDB[("User DB<br/>MySQL")]
                VaultDB[("Vault DB<br/>MySQL")]
                GenDB[("Generator DB<br/>MySQL")]
                SecDB[("Security DB<br/>MySQL")]
                NotifyDB[("Notification DB<br/>MySQL")]
            end
        end
        
        RDS["AWS RDS MySQL"]
    end
    
    UI --> ALB
    ALB --> Gateway
    Gateway --> User
    Gateway --> Vault
    Gateway --> Generator
    Gateway --> Security
    Gateway --> Notify
    
    User --> UserDB
    Vault --> VaultDB
    Generator --> GenDB
    Security --> SecDB
    Notify --> NotifyDB
    
    User --> Eureka
    Vault --> Eureka
    Generator --> Eureka
    Security --> Eureka
    Notify --> Eureka
    
    User --> Config
    Vault --> Config
    Generator --> Config
    Security --> Config
    Notify --> Config
```

### 2.3 Spring Cloud Stack Implementation

#### API Gateway (Spring Cloud Gateway)

```yaml
# api-gateway-service/application.yml
server:
  port: 8080

spring:
  application:
    name: api-gateway
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service
          predicates:
            - Path=/api/auth/**,/api/users/**,/api/2fa/**,/api/sessions/**
          filters:
            - StripPrefix=1
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10
                redis-rate-limiter.burstCapacity: 20
            - name: CircuitBreaker
              args:
                fallbackUri: forward:/fallback

        - id: vault-service
          uri: lb://vault-service
          predicates:
            - Path=/api/vault/**,/api/categories/**,/api/folders/**
          filters:
            - StripPrefix=1

        - id: generator-service
          uri: lb://generator-service
          predicates:
            - Path=/api/password-generator/**
          filters:
            - StripPrefix=1

        - id: security-service
          uri: lb://security-service
          predicates:
            - Path=/api/security/**,/api/dashboard/**,/api/backup/**
          filters:
            - StripPrefix=1

        - id: notification-service
          uri: lb://notification-service
          predicates:
            - Path=/api/notifications/**
          filters:
            - StripPrefix=1

        - id: sharing-service
          uri: lb://sharing-service
          predicates:
            - Path=/api/share/**
          filters:
            - StripPrefix=1

        - id: scheduler-service
          uri: lb://scheduler-service
          predicates:
            - Path=/api/scheduler/**
          filters:
            - StripPrefix=1

      default-filters:
        - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin

  redis:
    host: redis
    port: 6379

resilience4j:
  circuitbreaker:
    instances:
      user-service:
        slidingWindowSize: 10
        minimumNumberOfCalls: 5
        permittedNumberOfCallsInHalfOpenState: 3
        automaticTransitionFromOpenToHalfOpenEnabled: true
        waitDurationInOpenState: 5s
        failureRateThreshold: 50

eureka:
  client:
    register-with-eureka: true
    fetch-registry: true
    service-url:
      defaultZone: http://eureka-server:8761/eureka/
```

#### Eureka Server

```xml
<!-- eureka-server/pom.xml -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
</dependency>
```

```yaml
# eureka-server/application.yml
server:
  port: 8761

spring:
  application:
    name: eureka-server

eureka:
  instance:
    hostname: eureka-server
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://eureka-server:8761/eureka/
  server:
    enable-self-preservation: false
    eviction-interval-timer-in-ms: 5000
```

#### Config Server

```xml
<!-- config-server/pom.xml -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-config-server</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-consul-config</artifactId>
</dependency>
```

```yaml
# config-server/application.yml
server:
  port: 8888

spring:
  application:
    name: config-server
  cloud:
    config:
      server:
        consul:
          host: consul
          port: 8500
    consul:
      host: consul
      port: 8500
```

#### Service Registration Example (User Service)

```xml
<!-- user-service/pom.xml -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-config</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
<dependency>
    <groupId>io.github.resilience4j</groupId>
    <artifactId>resilience4j-spring-boot3</artifactId>
</dependency>
```

```yaml
# user-service/bootstrap.yml
spring:
  application:
    name: user-service
  cloud:
    config:
      uri: http://config-server:8888
      fail-fast: true
      retry:
        max-attempts: 6
        initial-interval: 1000
        multiplier: 1.5

# user-service/application.yml
server:
  port: 8081

eureka:
  client:
    register-with-eureka: true
    fetch-registry: true
    service-url:
      defaultZone: http://eureka-server:8761/eureka/
  instance:
    prefer-ip-address: true
    lease-renewal-interval-in-seconds: 10

resilience4j:
  circuitbreaker:
    instances:
      vaultService:
        slidingWindowSize: 10
        failureRateThreshold: 50

feign:
  client:
    config:
      default:
        connectTimeout: 5000
        readTimeout: 5000
  circuitbreaker:
    enabled: true
```

### 2.4 Inter-Service Communication

```java
// Feign Client Example
@FeignClient(name = "vault-service", fallback = VaultServiceFallback.class)
public interface VaultClient {
    
    @GetMapping("/api/entries/{id}")
    VaultEntryResponse getVaultEntry(@PathVariable("id") Long id);
    
    @PostMapping("/api/entries")
    VaultEntryResponse createEntry(@Body VaultEntryRequest request);
}

@Component
public class VaultServiceFallback implements VaultServiceFallback {
    
    @Override
    public VaultEntryResponse getVaultEntry(Long id) {
        throw new ServiceUnavailableException("Vault service is temporarily unavailable");
    }
    
    @Override
    public VaultEntryResponse createEntry(VaultEntryRequest request) {
        throw new ServiceUnavailableException("Vault service is temporarily unavailable");
    }
}

// Usage in User Service
@Service
public class UserService {
    
    @Autowired
    private VaultClient vaultClient;
    
    public VaultEntryResponse getUserVaultEntry(Long entryId) {
        return vaultClient.getVaultEntry(entryId);
    }
}
```

### 2.5 Kubernetes Orchestration (Minikube)

#### Kubernetes Deployment Example

```yaml
# kubernetes/user-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
  labels:
    app: user-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        ports:
        - containerPort: 8081
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "prod"
        - name: EUREKA_CLIENT_SERVICEURL_DEFAULTZONE
          value: "http://eureka-server:8761/eureka/"
        - name: SPRING_DATASOURCE_URL
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: url
        - name: SPRING_DATASOURCE_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: username
        - name: SPRING_DATASOURCE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: password
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8081
          initialDelaySeconds: 60
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 5
```

#### Kubernetes Service

```yaml
# kubernetes/user-service-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
  ports:
  - protocol: TCP
    port: 8081
    targetPort: 8081
  type: ClusterIP
```

#### Kubernetes Secrets

```yaml
# kubernetes/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secrets
type: Opaque
stringData:
  url: jdbc:mysql://mysql-service:3306/user_db
  username: root
  password: changeme
---
apiVersion: v1
kind: Secret
metadata:
  name: jwt-secrets
type: Opaque
stringData:
  jwt-secret: your-256-bit-secret-key
```

#### ConfigMap

```yaml
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  SPRING_PROFILES_ACTIVE: "prod"
  EUREKA_CLIENT_SERVICEURL_DEFAULTZONE: "http://eureka-server:8761/eureka/"
  SPRING_CLOUD_CONFIG_URI: "http://config-server:8888"
```

#### Horizontal Pod Autoscaler

```yaml
# kubernetes/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: user-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: user-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Ingress

```yaml
# kubernetes/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: password-manager-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: password-manager.local
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

### 2.6 Observability

#### ELK Stack for Logging

```yaml
# kubernetes/elk/elasticsearch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elasticsearch
spec:
  replicas: 1
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
        ports:
        - containerPort: 9200
        env:
        - name: discovery.type
          value: single-node
        - name: xpack.security.enabled
          value: "false"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
```

```yaml
# kubernetes/elk/logstash.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: logstash
spec:
  replicas: 1
  selector:
    matchLabels:
      app: logstash
  template:
    metadata:
      labels:
        app: logstash
    spec:
      containers:
      - name: logstash
        image: logstash:8.10.0
        ports:
        - containerPort: 5044
        volumeMounts:
        - name: logstash-config
          mountPath: /usr/share/logstash/pipeline
      volumes:
      - name: logstash-config
        configMap:
          name: logstash-config
```

#### Prometheus + Grafana

```yaml
# kubernetes/monitoring/prometheus.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:v2.45.0
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: prometheus-config
          mountPath: /etc/prometheus/prometheus.yml
      volumes:
      - name: prometheus-config
        configMap:
          name: prometheus-config
```

```yaml
# kubernetes/monitoring/grafana.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:10.0.0
        ports:
        - containerPort: 3000
        env:
        - name: GF_SECURITY_ADMIN_USER
          value: admin
        - name: GF_SECURITY_ADMIN_PASSWORD
          value: admin
```

#### Distributed Tracing with Jaeger

```yaml
# kubernetes/tracing/jaeger.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
      - name: jaeger
        image: jaegertracing/all-in-one:1.47
        ports:
        - containerPort: 16686
        - containerPort: 6831
```

### 2.7 Phase 2 Checklist

- [ ] Design domain-driven bounded contexts
- [ ] Create 5 microservices projects
- [ ] Set up Eureka Server
- [ ] Set up Config Server
- [ ] Implement API Gateway with routing
- [ ] Implement circuit breaker patterns
- [ ] Create Kubernetes deployments
- [ ] Create Kubernetes services
- [ ] Configure Kubernetes secrets
- [ ] Configure ConfigMaps
- [ ] Set up Horizontal Pod Autoscaler
- [ ] Configure Ingress
- [ ] Deploy ELK Stack
- [ ] Deploy Prometheus + Grafana
- [ ] Deploy Jaeger for tracing
- [ ] Test inter-service communication
- [ ] Verify Kubernetes orchestration

---

## Tech Stack Summary

| Category | Technology |
|----------|------------|
| Language | Java 17 |
| Framework | Spring Boot 3 |
| Cloud Framework | Spring Cloud |
| Frontend | Angular 18 |
| Containerization | Docker |
| Orchestration | Kubernetes (Minikube) |
| CI/CD | Jenkins |
| Cloud Provider | AWS (EC2, RDS, Secrets Manager, ECR, ALB) |
| Build Tool | Maven |
| Version Control | Git |
| Database | MySQL 8 |
| Logging | ELK Stack |
| Monitoring | Prometheus + Grafana |
| Service Communication | Feign |
| Service Discovery | Eureka |
| Circuit Breaker | Resilience4j |

---

## Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| Phase 1: Containerization | 6 weeks | Dockerfiles, AWS infrastructure, CI/CD pipeline |
| Phase 2: Microservices (7 services) | 14 weeks | 7 microservices, Kubernetes deployment, monitoring |

**Total Duration: 20 weeks**
