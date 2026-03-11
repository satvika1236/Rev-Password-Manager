package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.SecurityAuditResponse;
import com.revature.passwordmanager.dto.response.SecurityAuditResponse.VaultEntrySummary;
import com.revature.passwordmanager.model.security.PasswordAnalysis;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.PasswordAnalysisRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.util.EncryptionUtil;
import com.revature.passwordmanager.util.PasswordStrengthCalculator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SecurityAuditService {

  private static final Logger logger = LoggerFactory.getLogger(SecurityAuditService.class);
  private static final int OLD_PASSWORD_DAYS = 90;

  private final VaultEntryRepository vaultEntryRepository;
  private final UserRepository userRepository;
  private final EncryptionService encryptionService;
  private final EncryptionUtil encryptionUtil;
  private final PasswordStrengthCalculator passwordStrengthCalculator;
  private final PasswordAnalysisRepository passwordAnalysisRepository;

  @Transactional
  public void analyzeEntry(VaultEntry entry) {
    try {
      User user = entry.getUser();
      SecretKey key = encryptionUtil.deriveKey(user.getMasterPasswordHash(), user.getSalt());

      @SuppressWarnings("java:S2068") // Not a hardcoded
      //  password, just a placeholder string
      String password = "******";
      if (!Boolean.TRUE.equals(entry.getIsHighlySensitive())) {
        try {
          password = encryptionService.decrypt(entry.getPassword(), key);
        } catch (Exception e) {
          logger.error("Failed to decrypt newly created entry {} for analysis.", entry.getId());
          // If we fail to decrypt, we cannot grade the password accurately, but we should
          // not crash the save.
          return;
        }
      }

      int score = passwordStrengthCalculator.calculateScore(password);
      List<String> issues = generateIssues(password, score);

      List<VaultEntry> allEntries = vaultEntryRepository.findByUserIdAndIsDeletedFalse(user.getId());
      boolean isReused = false;
      int reuseCount = 0;

      for (VaultEntry other : allEntries) {
        if (!other.getId().equals(entry.getId()) && !Boolean.TRUE.equals(other.getIsHighlySensitive())) {
          try {
            @SuppressWarnings("java:S2068") // Not a hardcoded password, just a decrypted user password
            String otherPassword = encryptionService.decrypt(other.getPassword(), key);
            if (password.equals(otherPassword) && !password.equals("******")) {
              isReused = true;
              reuseCount++;

              // Ensure the other entry is also marked as reused
              PasswordAnalysis otherAnalysis = passwordAnalysisRepository.findByVaultEntryId(other.getId())
                  .orElse(PasswordAnalysis.builder().vaultEntry(other).build());
              if (!otherAnalysis.isReused()) {
                otherAnalysis.setReused(true);
                List<String> otherIssues = otherAnalysis.getIssues() != null
                    ? new ArrayList<>(otherAnalysis.getIssues())
                    : new ArrayList<>();

                if (!otherIssues.contains("Password reused")) {
                  otherIssues.add("Password reused");
                  otherAnalysis.setIssues(otherIssues);
                }
                otherAnalysis.setLastAnalyzed(LocalDateTime.now());
                passwordAnalysisRepository.save(otherAnalysis);
              }
            }
          } catch (Exception e) {
            logger.warn("Failed to decrypt entry {} for reuse check", other.getId());
          }
        }
      }

      if (isReused) {
        issues.add("Password reused " + reuseCount + " times");
      }

      PasswordAnalysis analysis = passwordAnalysisRepository.findByVaultEntryId(entry.getId())
          .orElse(PasswordAnalysis.builder().vaultEntry(entry).build());

      analysis.setStrengthScore(score);
      analysis.setReused(isReused);
      analysis.setIssues(issues);
      analysis.setLastAnalyzed(LocalDateTime.now());

      passwordAnalysisRepository.save(analysis);
      logger.debug("Analyzed entry {}: score={}, reused={}", entry.getId(), score, isReused);

    } catch (Exception e) {
      logger.error("Failed to analyze entry {}: {}", entry.getId(), e.getMessage());
    }
  }

  @Transactional
  public SecurityAuditResponse generateAuditReport(String username) {
    User user = userRepository.findByUsernameOrThrow(username);

    // Ensure all current entries have analysis data, backfilling if necessary
    List<VaultEntry> allEntries = vaultEntryRepository.findByUserIdAndIsDeletedFalse(user.getId());
    syncMissingAnalyses(user, allEntries);

    List<PasswordAnalysis> analyses = passwordAnalysisRepository.findByVaultEntryUserId(user.getId());

    List<VaultEntrySummary> weak = new ArrayList<>();
    List<VaultEntrySummary> reused = new ArrayList<>();
    List<VaultEntrySummary> old = new ArrayList<>();

    LocalDateTime cutoff = LocalDateTime.now().minusDays(OLD_PASSWORD_DAYS);

    for (PasswordAnalysis analysis : analyses) {
      VaultEntry entry = analysis.getVaultEntry();
      if (entry == null || Boolean.TRUE.equals(entry.getIsDeleted()))
        continue;

      if (analysis.getStrengthScore() < 60) {
        weak.add(mapToSummary(entry, "Weak password (score: " + analysis.getStrengthScore() + "/100)"));
      }

      if (analysis.isReused()) {
        reused.add(mapToSummary(entry, "Password is reused"));
      }

      if (entry.getUpdatedAt() != null && entry.getUpdatedAt().isBefore(cutoff)) {
        old.add(mapToSummary(entry, "Password not updated in over " + OLD_PASSWORD_DAYS + " days"));
      }
    }

    int total = analyses.size();
    int securityScore = calculateSecurityScore(total, weak.size(), reused.size(), old.size());
    List<String> recommendations = generateRecommendations(weak.size(), reused.size(), old.size());

    return SecurityAuditResponse.builder()
        .totalEntries(total)
        .weakCount(weak.size())
        .reusedCount(reused.size())
        .oldCount(old.size())
        .securityScore(securityScore)
        .recommendations(recommendations)
        .weakPasswords(weak)
        .reusedPasswords(reused)
        .oldPasswords(old)
        .build();
  }

  @Transactional(readOnly = true)
  public List<VaultEntrySummary> getWeakPasswords(String username) {
    return generateAuditReport(username).getWeakPasswords();
  }

  @Transactional(readOnly = true)
  public List<VaultEntrySummary> getReusedPasswords(String username) {
    return generateAuditReport(username).getReusedPasswords();
  }

  @Transactional(readOnly = true)
  public List<VaultEntrySummary> getOldPasswords(String username) {
    return generateAuditReport(username).getOldPasswords();
  }

  private VaultEntrySummary mapToSummary(VaultEntry entry, String issue) {
    return VaultEntrySummary.builder()
        .id(entry.getId())
        .title(entry.getTitle())
        .websiteUrl(entry.getWebsiteUrl())
        .issue(issue)
        .build();
  }

  private int calculateSecurityScore(int total, int weak, int reused, int old) {
    if (total == 0)
      return 100;
    int issues = weak + reused + old;
    double ratio = 1.0 - ((double) issues / (total * 3));
    return Math.max(0, Math.min(100, (int) (ratio * 100)));
  }

  private List<String> generateIssues(String password, int score) {
    List<String> issues = new ArrayList<>();
    if (password.length() < 8)
      issues.add("Too short");
    if (score < 60)
      issues.add("Weak complexity");
    return issues;
  }

  private List<String> generateRecommendations(int weak, int reused, int old) {
    List<String> recommendations = new ArrayList<>();
    if (weak > 0)
      recommendations.add("Update " + weak + " weak password(s)");
    if (reused > 0)
      recommendations.add("Change " + reused + " reused password(s)");
    if (old > 0)
      recommendations.add("Rotate " + old + " old password(s)");
    if (recommendations.isEmpty())
      recommendations.add("Your vault security is excellent!");
    return recommendations;
  }

  private void syncMissingAnalyses(User user, List<VaultEntry> allEntries) {
    List<PasswordAnalysis> existingAnalyses = passwordAnalysisRepository.findByVaultEntryUserId(user.getId());
    Set<Long> analyzedEntryIds = existingAnalyses.stream()
        .map(a -> a.getVaultEntry().getId())
        .collect(Collectors.toSet());

    // Force a full re-analysis if we are missing any entries (to fix old bad data)
    // Or if there are no existing analyses but we have entries
    boolean needSync = false;
    for (VaultEntry entry : allEntries) {
      if (!analyzedEntryIds.contains(entry.getId())) {
        needSync = true;
        break;
      }
    }

    // Since previous bugs might have left isReused in a bad state, we just do a
    // full scan
    // for missing ones to ensure accuracy. If we find missing ones, we re-evaluate
    // everything.
    if (needSync) {
      logger.info("Found missing password analysis data for user {}. Running full re-scan.", user.getUsername());
      for (VaultEntry entry : allEntries) {
        if (!analyzedEntryIds.contains(entry.getId())) {
          analyzeEntry(entry);
        }
      }
    }
  }
}
