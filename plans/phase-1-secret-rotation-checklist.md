# Phase 1 Secret Rotation Checklist

Use this checklist whenever AWS application secrets or database credentials are rotated.

## Secrets in scope

- `/<project>-<environment>/database`
- `/<project>-<environment>/application`

## Rotation steps

1. Rotate the target secret in AWS Secrets Manager.
2. If the database password changed, update the RDS credential first and confirm the new credential works before restarting the app.
3. Verify the secret JSON still contains the expected keys:
   - database secret:
     - `SPRING_DATASOURCE_URL`
     - `SPRING_DATASOURCE_USERNAME`
     - `SPRING_DATASOURCE_PASSWORD`
   - application secret:
     - `JWT_SECRET`
     - `JWT_ACCESS_TOKEN_EXPIRATION`
     - `JWT_REFRESH_TOKEN_EXPIRATION`
     - `SPRING_MAIL_HOST`
     - `SPRING_MAIL_PORT`
     - `SPRING_MAIL_USERNAME`
     - `SPRING_MAIL_PASSWORD`
     - `AI_OPENAI_API_KEY`
4. Trigger an Auto Scaling Group instance refresh so new instances bootstrap with the rotated secret values.
5. Watch ALB target health until all new targets return healthy.
6. Run the Phase 1 smoke test set against the deployed ALB URL.
7. Confirm CloudWatch logs show healthy startup for both containers.

## Post-rotation validation

- `GET /actuator/health` returns healthy through the ALB.
- Login works with the rotated JWT secret in effect.
- Mail-dependent flows still succeed if SMTP credentials were changed.
- No authentication or datasource failures appear in CloudWatch logs.

## Rollback trigger

If the rotated secret causes startup or runtime failures, revert the previous secret value and run another ASG instance refresh immediately.
