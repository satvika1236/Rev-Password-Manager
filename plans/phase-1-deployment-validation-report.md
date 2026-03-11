# Phase 1 Deployment Validation Report

Use this document to record the first successful AWS deployment and each significant redeploy after infrastructure changes.

## Deployment details

- Date:
- Commit SHA:
- Terraform workspace or var-file:
- ALB DNS name:
- ASG name:
- Backend image tag:
- Frontend image tag:

## Infrastructure validation

- [ ] Terraform apply completed without errors
- [ ] ALB created and reachable
- [ ] EC2 instances launched in the Auto Scaling Group
- [ ] RDS MySQL Multi-AZ instance available
- [ ] Backend and frontend ECR repositories populated
- [ ] Secrets Manager entries created

## Health validation

- [ ] Frontend target group healthy
- [ ] Backend target group healthy
- [ ] `GET /healthz` returns `200`
- [ ] `GET /actuator/health` returns `200`
- [ ] CloudWatch logs show clean startup for frontend
- [ ] CloudWatch logs show clean startup for backend

## Smoke tests

- [ ] Frontend root path loads
- [ ] User login works
- [ ] Vault list loads
- [ ] Create vault entry works
- [ ] Backup export works
- [ ] Logout works

## Notes

- Issues found:
- Follow-up actions:
