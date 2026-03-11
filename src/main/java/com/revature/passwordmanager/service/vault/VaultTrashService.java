package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.response.TrashEntryResponse;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultTrashRepository;
import com.revature.passwordmanager.repository.VaultSnapshotRepository;
import com.revature.passwordmanager.repository.PasswordAnalysisRepository;
import com.revature.passwordmanager.repository.SecureShareRepository;
import com.revature.passwordmanager.service.notification.NotificationService;
import com.revature.passwordmanager.model.notification.Notification.NotificationType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultTrashService {

  private static final Logger logger = LoggerFactory.getLogger(VaultTrashService.class);
  private static final int TRASH_RETENTION_DAYS = 30;

  private final VaultTrashRepository vaultTrashRepository;
  private final UserRepository userRepository;
  private final VaultSnapshotRepository vaultSnapshotRepository;
  private final PasswordAnalysisRepository passwordAnalysisRepository;
  private final NotificationService notificationService;
  private final SecureShareRepository secureShareRepository;

  @Transactional(readOnly = true)
  public List<TrashEntryResponse> getTrashEntries(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    List<VaultEntry> entries = vaultTrashRepository.findByUserIdAndIsDeletedTrue(user.getId());
    return entries.stream()
        .map(this::mapToTrashResponse)
        .collect(Collectors.toList());
  }

  @Transactional(readOnly = true)
  public long getTrashCount(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    return vaultTrashRepository.countByUserIdAndIsDeletedTrue(user.getId());
  }

  @Transactional
  public TrashEntryResponse restoreEntry(String username, Long entryId) {
    User user = userRepository.findByUsernameOrThrow(username);
    VaultEntry entry = vaultTrashRepository.findByIdAndUserIdAndIsDeletedTrue(entryId, user.getId())
        .orElseThrow(() -> new ResourceNotFoundException("Trashed entry not found"));

    entry.setIsDeleted(false);
    entry.setDeletedAt(null);
    vaultTrashRepository.save(entry);

    notificationService.createNotification(username, NotificationType.ACCOUNT_ACTIVITY, "Vault Entry Restored",
        "You restored the vault entry '" + entry.getTitle() + "' from the trash.");

    logger.info("Restored vault entry {} for user {}", entryId, username);
    return mapToTrashResponse(entry);
  }

  @Transactional
  public void restoreAll(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    List<VaultEntry> trashedEntries = vaultTrashRepository.findByUserIdAndIsDeletedTrue(user.getId());

    trashedEntries.forEach(entry -> {
      entry.setIsDeleted(false);
      entry.setDeletedAt(null);
    });

    vaultTrashRepository.saveAll(trashedEntries);

    notificationService.createNotification(username, NotificationType.ACCOUNT_ACTIVITY, "Trash Restored",
        "You restored " + trashedEntries.size() + " items from the trash.");

    logger.info("Restored {} trashed entries for user {}", trashedEntries.size(), username);
  }

  @Transactional
  public void permanentDelete(String username, Long entryId) {
    User user = userRepository.findByUsernameOrThrow(username);
    VaultEntry entry = vaultTrashRepository.findByIdAndUserIdAndIsDeletedTrue(entryId, user.getId())
        .orElseThrow(() -> new ResourceNotFoundException("Trashed entry not found"));

    vaultSnapshotRepository.deleteByVaultEntryId(entry.getId());
    passwordAnalysisRepository.deleteByVaultEntryId(entry.getId());

    vaultTrashRepository.delete(entry);

    notificationService.createNotification(username, NotificationType.ACCOUNT_ACTIVITY,
        "Vault Entry Permanently Deleted",
        "You permanently deleted the vault entry '" + entry.getTitle() + "' from the trash.");

    logger.info("Permanently deleted vault entry {} for user {}", entryId, username);
  }

  @Transactional
  public void emptyTrash(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    List<VaultEntry> trashedEntries = vaultTrashRepository.findByUserIdAndIsDeletedTrue(user.getId());

    trashedEntries.forEach(entry -> {
      vaultSnapshotRepository.deleteByVaultEntryId(entry.getId());
      passwordAnalysisRepository.deleteByVaultEntryId(entry.getId());
    });

    vaultTrashRepository.deleteAll(trashedEntries);

    notificationService.createNotification(username, NotificationType.ACCOUNT_ACTIVITY, "Trash Emptied",
        "You emptied " + trashedEntries.size() + " items from the trash permanently.");

    logger.info("Emptied trash ({} entries) for user {}", trashedEntries.size(), username);
  }

  @Transactional
  public void cleanupExpired() {
    LocalDateTime expiry = LocalDateTime.now().minusDays(TRASH_RETENTION_DAYS);
    List<VaultEntry> expired = vaultTrashRepository.findExpiredTrashEntries(expiry);

    if (!expired.isEmpty()) {
      expired.forEach(entry -> {
        vaultSnapshotRepository.deleteByVaultEntryId(entry.getId());
        passwordAnalysisRepository.deleteByVaultEntryId(entry.getId());
      });
      vaultTrashRepository.deleteAll(expired);
      logger.info("Cleaned up {} expired trash entries", expired.size());
    }
  }

  private TrashEntryResponse mapToTrashResponse(VaultEntry entry) {
    LocalDateTime expiresAt = entry.getDeletedAt() != null
        ? entry.getDeletedAt().plusDays(TRASH_RETENTION_DAYS)
        : null;
    long daysRemaining = expiresAt != null
        ? Math.max(0, ChronoUnit.DAYS.between(LocalDateTime.now(), expiresAt))
        : 0;

    return TrashEntryResponse.builder()
        .id(entry.getId())
        .title(entry.getTitle())
        .websiteUrl(entry.getWebsiteUrl())
        .categoryName(entry.getCategory() != null ? entry.getCategory().getName() : null)
        .folderName(entry.getFolder() != null ? entry.getFolder().getName() : null)
        .deletedAt(entry.getDeletedAt())
        .expiresAt(expiresAt)
        .daysRemaining(daysRemaining)
        .build();
  }
}
