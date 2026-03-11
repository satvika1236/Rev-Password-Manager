# Pre-Phase 0 Smoke Test Checklist

Date created: 2026-03-07

## Goal

Establish a repeatable baseline before Phase 1 containerization and Phase 2 extraction work starts.

## Required environment

- Backend profile: `local`
- Frontend target: `http://localhost:4200`
- Backend target: `http://localhost:8080`
- Database: MySQL 8.0 with the credentials from local environment variables

## Automated baseline commands

Backend:

```bash
mvn test -q
```

Frontend:

```bash
cd frontend
npm test -- --watch=false --browsers=ChromeHeadless
```

## Critical flow checklist

- [ ] Register a new user account
- [ ] Verify email OTP after registration
- [ ] Login with username/email and master password
- [ ] Refresh access token
- [ ] Enable 2FA and verify one login with OTP
- [ ] Create a vault entry
- [ ] View a sensitive vault entry after re-authentication
- [ ] Generate a password from the generator UI
- [ ] Export a backup
- [ ] Open notifications and mark one as read

## Results log

### Automated checks

- [x] Backend test suite passed
- [x] Frontend test suite passed

Executed on 2026-03-07:

- Backend: `mvn test -q` completed with 630 tests, 0 failures, 0 errors.
- Frontend: `npm test -- --watch=false --browsers=ChromeHeadless` completed with 215 passing specs.

### Manual smoke execution

- [ ] Local backend started with `local` profile
- [ ] Local frontend started and reached the login page
- [ ] All critical flows above were executed successfully

Current status:

- Automated baseline is green.
- Manual end-to-end smoke execution is still required before Pre-Phase 0 can be closed completely.

## Notes

- Record any failing endpoint, UI regression, or data setup dependency before Phase 1 starts.
- If SMTP is not configured locally, use a fake SMTP server such as MailHog or equivalent before validating email-dependent flows.
