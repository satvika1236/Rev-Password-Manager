package com.revature.passwordmanager.service.user;

import com.revature.passwordmanager.dto.request.ChangePasswordRequest;
import com.revature.passwordmanager.dto.request.UpdateProfileRequest;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.NotificationRepository;
import com.revature.passwordmanager.dto.response.DashboardResponse;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.util.EncryptionUtil;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;
  private final VaultEntryRepository vaultEntryRepository;
  private final CategoryRepository categoryRepository;
  private final FolderRepository folderRepository;
  private final NotificationRepository notificationRepository;
  private final PasswordEncoder passwordEncoder;
  private final com.revature.passwordmanager.service.security.SecurityAuditService securityAuditService;
  private final EncryptionService encryptionService;
  private final EncryptionUtil encryptionUtil;

  @Transactional(readOnly = true)
  public UserResponse getUserProfile(String username) {
    User user = userRepository.findByUsernameOrThrow(username);

    return UserResponse.builder()
        .id(user.getId())
        .email(user.getEmail())
        .username(user.getUsername())
        .name(user.getName())
        .phoneNumber(user.getPhoneNumber())
        .is2faEnabled(user.is2faEnabled())
        .createdAt(user.getCreatedAt())
        .deletionScheduledAt(user.getDeletionScheduledAt())
        .build();
  }

  @Transactional
  public UserResponse updateProfile(String username, UpdateProfileRequest request) {
    User user = userRepository.findByUsernameOrThrow(username);

    if (request.getName() != null) {
      user.setName(request.getName());
    }
    if (request.getPhoneNumber() != null) {
      user.setPhoneNumber(request.getPhoneNumber());
    }
    if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
      if (userRepository.existsByEmail(request.getEmail())) {
        throw new IllegalArgumentException("Email address is already in use by another account.");
      }
      user.setEmail(request.getEmail());
    }

    User savedUser = userRepository.save(user);

    return UserResponse.builder()
        .id(savedUser.getId())
        .email(savedUser.getEmail())
        .username(savedUser.getUsername())
        .name(savedUser.getName())
        .phoneNumber(savedUser.getPhoneNumber())
        .is2faEnabled(savedUser.is2faEnabled())
        .createdAt(savedUser.getCreatedAt())
        .build();
  }

  @Transactional
  public void changeMasterPassword(String username, ChangePasswordRequest request) {
    log.info("Starting master password change for user: {}", username);
    User user = userRepository.findByUsernameOrThrow(username);

    if (!passwordEncoder.matches(request.getOldPassword(), user.getMasterPasswordHash())) {
      log.warn("Old password verification failed for user: {}", username);
      throw new AuthenticationException("Invalid old password");
    }

    // Derive the OLD encryption key from the current master password hash
    SecretKey oldKey = encryptionUtil.deriveKey(user.getMasterPasswordHash(), user.getSalt());
    log.info("Derived old encryption key for user: {}", username);

    // Update the master password hash to the NEW password
    String newPasswordHash = passwordEncoder.encode(request.getNewPassword());
    String oldHashPrefix = user.getMasterPasswordHash().substring(0,
        Math.min(20, user.getMasterPasswordHash().length()));
    String newHashPrefix = newPasswordHash.substring(0, Math.min(20, newPasswordHash.length()));
    log.info("Updating password hash from [{}...] to [{}...]", oldHashPrefix, newHashPrefix);
    user.setMasterPasswordHash(newPasswordHash);

    // Derive the NEW encryption key from the new master password hash
    SecretKey newKey = encryptionUtil.deriveKey(newPasswordHash, user.getSalt());
    log.info("Derived new encryption key for user: {}", username);

    // Re-encrypt all vault entries with the new key
    List<VaultEntry> entries = vaultEntryRepository.findByUserIdAndIsDeletedFalse(user.getId());
    log.info("Found {} vault entries to re-encrypt for user: {}", entries.size(), username);

    int successCount = 0;
    for (VaultEntry entry : entries) {
      try {
        // Decrypt with old key
        String decryptedPassword = encryptionService.decrypt(entry.getPassword(), oldKey);
        String decryptedUsername = encryptionService.decrypt(entry.getUsername(), oldKey);
        String decryptedNotes = entry.getNotes() != null && !entry.getNotes().isEmpty()
            ? encryptionService.decrypt(entry.getNotes(), oldKey)
            : "";

        // Re-encrypt with new key
        entry.setPassword(encryptionService.encrypt(decryptedPassword, newKey));
        entry.setUsername(encryptionService.encrypt(decryptedUsername, newKey));
        if (entry.getNotes() != null && !entry.getNotes().isEmpty()) {
          entry.setNotes(encryptionService.encrypt(decryptedNotes, newKey));
        }
        successCount++;
      } catch (Exception e) {
        log.error("Failed to re-encrypt vault entry {} ({}): {}", entry.getId(), entry.getTitle(), e.getMessage());
        throw new RuntimeException("Failed to re-encrypt vault entry: " + entry.getTitle(), e);
      }
    }

    log.info("Successfully re-encrypted {}/{} entries for user: {}", successCount, entries.size(), username);

    // Save all re-encrypted entries
    vaultEntryRepository.saveAll(entries);
    log.info("Saved all re-encrypted entries for user: {}", username);

    // Save the user with new password hash
    userRepository.save(user);
    log.info("Master password change completed successfully for user: {}", username);
  }

  @Transactional
  public DashboardResponse getDashboardData(String username) {
    User user = userRepository.findByUsernameOrThrow(username);

    int vaultEntries = (int) vaultEntryRepository.countByUserAndIsDeletedFalse(user);
    int favorites = (int) vaultEntryRepository.countByUserAndIsFavoriteTrue(user);
    int categories = (int) categoryRepository.countByUser(user);
    int folders = (int) folderRepository.countByUser(user);
    int unreadNotifications = (int) notificationRepository.countByUserAndIsReadFalse(user);

    var auditReport = securityAuditService.generateAuditReport(username);

    return DashboardResponse.builder()
        .totalVaultEntries(vaultEntries)
        .totalCategories(categories)
        .totalFolders(folders)
        .totalFavorites(favorites)
        .weakPasswordsCount(auditReport.getWeakCount())
        .reusedPasswordsCount(auditReport.getReusedCount())
        .oldPasswordsCount(auditReport.getOldCount())
        .unreadNotifications(unreadNotifications)
        .build();
  }
}
