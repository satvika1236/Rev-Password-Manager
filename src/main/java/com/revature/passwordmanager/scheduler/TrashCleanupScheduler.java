package com.revature.passwordmanager.scheduler;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.revature.passwordmanager.service.vault.VaultTrashService;

@Component
@RequiredArgsConstructor
public class TrashCleanupScheduler {

  private static final Logger logger = LoggerFactory.getLogger(TrashCleanupScheduler.class);
  private final VaultTrashService vaultTrashService;

  @Scheduled(cron = "0 0 0 * * ?")
  public void cleanupExpiredTrash() {
    logger.info("Running scheduled trash cleanup task...");
    vaultTrashService.cleanupExpired();
    logger.info("Trash cleanup task completed.");
  }
}
