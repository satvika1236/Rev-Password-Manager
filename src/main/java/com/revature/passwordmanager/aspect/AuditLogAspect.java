package com.revature.passwordmanager.aspect;

import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.service.security.AuditLogService;

import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import com.revature.passwordmanager.service.vault.VaultTrashService;

@Aspect
@Component
@RequiredArgsConstructor
public class AuditLogAspect {

  private static final Logger logger = LoggerFactory.getLogger(AuditLogAspect.class);
  private final AuditLogService auditLogService;

  @AfterReturning("execution(* com.revature.passwordmanager.service.vault.VaultTrashService.restoreEntry(..))")
  public void logRestore(JoinPoint joinPoint) {
    try {
      String username = (String) joinPoint.getArgs()[0];
      Long entryId = (Long) joinPoint.getArgs()[1];
      auditLogService.logAction(username, AuditAction.ENTRY_RESTORED,
          "Restored vault entry ID: " + entryId);
    } catch (Exception e) {
      logger.error("Audit aspect error: {}", e.getMessage());
    }
  }

  @AfterReturning("execution(* com.revature.passwordmanager.service.vault.VaultTrashService.restoreAll(..))")
  public void logRestoreAll(JoinPoint joinPoint) {
    try {
      String username = (String) joinPoint.getArgs()[0];
      auditLogService.logAction(username, AuditAction.ENTRY_RESTORED,
          "Restored all trashed entries");
    } catch (Exception e) {
      logger.error("Audit aspect error: {}", e.getMessage());
    }
  }
}
