# Smoke Test Checklist

## Pre-Phase 0 Baseline Tests

### Backend Smoke Tests

#### Authentication Flow
- [ ] **Register new user** - POST `/api/auth/register`
  - [ ] Valid registration returns 201
  - [ ] Duplicate email returns 409
  - [ ] Invalid email format returns 400

- [ ] **Login** - POST `/api/auth/login`
  - [ ] Valid credentials return JWT tokens
  - [ ] Invalid password returns 401
  - [ ] Non-existent user returns 404

- [ ] **Refresh Token** - POST `/api/auth/refresh`
  - [ ] Valid refresh token returns new access token
  - [ ] Expired refresh token returns 401

- [ ] **2FA Setup** - POST `/api/2fa/setup`
  - [ ] Returns QR code for TOTP setup
  - [ ] Valid verification enables 2FA

#### Vault Operations
- [ ] **Create vault entry** - POST `/api/vault/entries`
  - [ ] Entry created with encryption
  - [ ] Invalid data returns 400

- [ ] **View sensitive entry** - GET `/api/vault/entries/{id}`
  - [ ] Requires master password
  - [ ] Returns decrypted sensitive data

- [ ] **List vault entries** - GET `/api/vault/entries`
  - [ ] Returns encrypted entries (not sensitive data)

#### Password Generator
- [ ] **Generate password** - GET `/api/password-generator/generate`
  - [ ] Returns generated password
  - [ ] Respects parameters (length, complexity)

#### Backup/Export
- [ ] **Export vault** - GET `/api/backup/export`
  - [ ] Returns encrypted JSON export

### Frontend Smoke Tests

- [ ] **Build test** - `npm run build`
  - [ ] Builds without errors
  
- [ ] **Unit tests** - `npm test`
  - [ ] Tests run successfully

### Critical Integration Flows

1. **User Registration Flow**
   - Register → Email verification → Login → Create vault entry

2. **Vault Access Flow**
   - Login → Enter master password → View vault → View entry details

3. **Password Generation Flow**
   - Login → Open generator → Generate password → Save to vault

4. **2FA Setup Flow**
   - Login → Navigate to security → Enable 2FA → Scan QR → Verify

---

## Test Execution Commands

### Backend
```bash
# Set JAVA_HOME
export JAVA_HOME=/path/to/jdk-21

# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=VaultServiceTest

# Run with coverage
mvn verify
```

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Run unit tests
npm test -- --watch=false

# Build for production
npm run build
```

---

## Known Issues / Notes

- Backend tests require Java 21 to be installed and JAVA_HOME configured
- Frontend tests require Node.js 20.x
- Integration tests require MySQL 8.0 database
- Email tests require SMTP configuration (or mock)
