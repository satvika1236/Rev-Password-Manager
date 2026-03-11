# Phase 1 Rollback Checklist

This rollback procedure assumes Phase 1 deploys are performed by pushing new images to ECR and then triggering an Auto Scaling Group instance refresh.

## Immediate rollback steps

1. Identify the last known-good backend and frontend image tags in ECR.
2. Retag the known-good images as `latest` or update the deployment process to point to the known-good tags.
3. Trigger a new ASG instance refresh.
4. Watch both target groups until healthy targets return.
5. Re-run the smoke test set against the ALB endpoint.

## If the issue is secret-related

1. Restore the previous secret values in AWS Secrets Manager.
2. Trigger another ASG instance refresh after the rollback values are in place.
3. Confirm datasource and authentication startup logs are healthy.

## If the issue is infrastructure-related

1. Revert the Terraform change in source control.
2. Run `terraform plan` to confirm only the intended rollback is present.
3. Apply the rollback plan.
4. Validate ALB, ASG, and RDS health before restoring traffic confidence.

## Success criteria

- Frontend root path responds normally
- Backend health endpoint returns healthy
- No startup exceptions remain in CloudWatch logs
- Login and one core vault flow succeed
