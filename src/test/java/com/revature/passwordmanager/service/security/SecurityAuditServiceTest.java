package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.SecurityAuditResponse;
import com.revature.passwordmanager.model.security.PasswordAnalysis;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.PasswordAnalysisRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.util.PasswordStrengthCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityAuditServiceTest {

  @Mock
  private VaultEntryRepository vaultEntryRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private EncryptionService encryptionService;
  @Mock
  private PasswordStrengthCalculator passwordStrengthCalculator;
  @Mock
  private PasswordAnalysisRepository passwordAnalysisRepository;
  @Mock
  private com.revature.passwordmanager.util.EncryptionUtil encryptionUtil;

  @InjectMocks
  private SecurityAuditService securityAuditService;

  private User user;
  private SecretKey mockKey;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .username("testuser")
        .masterPasswordHash("hash")
        .salt("c2FsdA==")
        .build();
    mockKey = mock(SecretKey.class);
  }

  @Test
  void generateAuditReport_EmptyVault_ShouldReturnPerfectScore() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(Collections.emptyList());

    SecurityAuditResponse report = securityAuditService.generateAuditReport("testuser");

    assertEquals(0, report.getTotalEntries());
    assertEquals(100, report.getSecurityScore());
    assertEquals(0, report.getWeakCount());
  }

  @Test
  void generateAuditReport_WithWeakPassword_ShouldFlag() {
    VaultEntry entry = VaultEntry.builder()
        .id(1L).user(user).title("Test Site")
        .build();
    PasswordAnalysis analysis = PasswordAnalysis.builder()
        .vaultEntry(entry)
        .strengthScore(30)
        .isReused(false)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(List.of(analysis));

    SecurityAuditResponse report = securityAuditService.generateAuditReport("testuser");

    assertEquals(1, report.getTotalEntries());
    assertEquals(1, report.getWeakCount());
    assertFalse(report.getWeakPasswords().isEmpty());
  }

  @Test
  void generateAuditReport_WithReusedPasswords_ShouldFlag() {
    VaultEntry entry = VaultEntry.builder().id(1L).user(user).title("Site A").build();
    PasswordAnalysis analysis = PasswordAnalysis.builder()
        .vaultEntry(entry)
        .strengthScore(80)
        .isReused(true)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(List.of(analysis));

    SecurityAuditResponse report = securityAuditService.generateAuditReport("testuser");

    assertEquals(1, report.getReusedCount());
    assertEquals(1, report.getTotalEntries());
  }

  @Test
  void getWeakPasswords_ShouldReturnOnlyWeak() {
    VaultEntry entry = VaultEntry.builder()
        .id(1L).user(user).title("Test Site")
        .build();
    PasswordAnalysis analysis = PasswordAnalysis.builder()
        .vaultEntry(entry)
        .strengthScore(30)
        .isReused(false)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(List.of(analysis));

    List<SecurityAuditResponse.VaultEntrySummary> weak = securityAuditService.getWeakPasswords("testuser");

    assertFalse(weak.isEmpty());
    assertEquals("Test Site", weak.get(0).getTitle());
  }

  @Test
  void getReusedPasswords_ShouldReturnOnlyReused() {
    VaultEntry entry = VaultEntry.builder().id(1L).user(user).title("Site A").build();
    PasswordAnalysis analysis = PasswordAnalysis.builder()
        .vaultEntry(entry)
        .strengthScore(80)
        .isReused(true)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(List.of(analysis));

    List<SecurityAuditResponse.VaultEntrySummary> reused = securityAuditService.getReusedPasswords("testuser");

    assertFalse(reused.isEmpty());
    assertEquals("Site A", reused.get(0).getTitle());
  }

  @Test
  void getOldPasswords_ShouldReturnOnlyOld() {
    VaultEntry entry = VaultEntry.builder().id(1L).user(user).title("Old Site")
        .updatedAt(LocalDateTime.now().minusDays(100)).build();
    PasswordAnalysis analysis = PasswordAnalysis.builder()
        .vaultEntry(entry)
        .strengthScore(80)
        .isReused(false)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordAnalysisRepository.findByVaultEntryUserId(1L)).thenReturn(List.of(analysis));

    List<SecurityAuditResponse.VaultEntrySummary> old = securityAuditService.getOldPasswords("testuser");

    assertFalse(old.isEmpty());
    assertEquals("Old Site", old.get(0).getTitle());
  }

  @Test
  void analyzeEntry_ShouldCalculateAndSave() {
    VaultEntry entry = VaultEntry.builder()
        .id(1L).user(user).title("Test Site")
        .password("encrypted")
        .build();

    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    try {
      when(encryptionService.decrypt("encrypted", mockKey)).thenReturn("password123");
    } catch (Exception e) {
    }
    when(passwordStrengthCalculator.calculateScore("password123")).thenReturn(50);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(entry));
    when(passwordAnalysisRepository.findByVaultEntryId(1L)).thenReturn(Optional.empty());

    securityAuditService.analyzeEntry(entry);

    verify(passwordAnalysisRepository).save(any(PasswordAnalysis.class));
  }
}
