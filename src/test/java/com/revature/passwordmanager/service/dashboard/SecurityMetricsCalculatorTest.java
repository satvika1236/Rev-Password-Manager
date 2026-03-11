package com.revature.passwordmanager.service.dashboard;

import com.revature.passwordmanager.dto.response.PasswordAgeResponse;
import com.revature.passwordmanager.dto.response.PasswordHealthMetricsResponse;
import com.revature.passwordmanager.dto.response.ReusedPasswordResponse;
import com.revature.passwordmanager.dto.response.SecurityScoreResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Category;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.util.EncryptionUtil;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityMetricsCalculatorTest {

    @Mock
    private VaultEntryRepository vaultEntryRepository;

    @Mock
    private PasswordStrengthCalculator passwordStrengthCalculator;

    @Mock
    private EncryptionService encryptionService;

    @Mock
    private EncryptionUtil encryptionUtil;

    @InjectMocks
    private SecurityMetricsCalculator calculator;

    private User user;
    private SecretKey mockKey;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .masterPasswordHash("hashedPassword")
                .salt("randomsalt")
                .build();

        mockKey = mock(SecretKey.class);
    }

    // ── calculateSecurityScore ────────────────────────────────────────────────

    @Test
    void calculateSecurityScore_EmptyVault_ShouldReturn100() {
        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(Collections.emptyList());

        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(100, result.getOverallScore());
        assertEquals("Excellent", result.getScoreLabel());
        assertEquals(0, result.getTotalPasswords());
    }

    @Test
    void calculateSecurityScore_AllStrongPasswords_ShouldHaveHighScore() {
        VaultEntry entry = buildEntry(1L, "Gmail", user, LocalDateTime.now().minusDays(5));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("Str0ng!Pass#2024");
        when(passwordStrengthCalculator.calculateScore("Str0ng!Pass#2024")).thenReturn(90);
        when(passwordStrengthCalculator.getStrengthLabel(90)).thenReturn("Strong");

        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(1, result.getTotalPasswords());
        assertEquals(0, result.getWeakPasswords());
        assertEquals(0, result.getReusedPasswords());
    }

    @Test
    void calculateSecurityScore_WithWeakPasswords_ShouldLowerScore() {
        VaultEntry weakEntry1 = buildEntry(1L, "Gmail", user, LocalDateTime.now().minusDays(5));
        VaultEntry weakEntry2 = buildEntry(2L, "Yahoo", user, LocalDateTime.now().minusDays(5));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(weakEntry1, weakEntry2));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey)))
                .thenReturn("weak1")
                .thenReturn("weak2");
        when(passwordStrengthCalculator.calculateScore(anyString())).thenReturn(15);
        when(passwordStrengthCalculator.getStrengthLabel(15)).thenReturn("Very Weak");

        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(2, result.getWeakPasswords());
        assertTrue(result.getOverallScore() < 100);
    }

    @Test
    void calculateSecurityScore_WithReusedPasswords_ShouldDetectReuse() {
        VaultEntry entry1 = buildEntry(1L, "Gmail", user, LocalDateTime.now().minusDays(5));
        VaultEntry entry2 = buildEntry(2L, "Yahoo", user, LocalDateTime.now().minusDays(5));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry1, entry2));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        // Both return the same password — simulates reuse
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("SamePassword123!");
        when(passwordStrengthCalculator.calculateScore("SamePassword123!")).thenReturn(70);
        when(passwordStrengthCalculator.getStrengthLabel(70)).thenReturn("Good");

        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(2, result.getReusedPasswords());
    }

    @Test
    void calculateSecurityScore_WithOldPasswords_ShouldDetectAge() {
        // Entry updated 100 days ago — over the 90-day threshold
        VaultEntry oldEntry = buildEntry(1L, "OldEntry", user, LocalDateTime.now().minusDays(100));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(oldEntry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("SomePassword1!");
        when(passwordStrengthCalculator.calculateScore("SomePassword1!")).thenReturn(65);
        when(passwordStrengthCalculator.getStrengthLabel(65)).thenReturn("Good");

        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(1, result.getOldPasswords());
    }

    @Test
    void calculateSecurityScore_DecryptionFailure_ShouldHandleGracefully() {
        VaultEntry entry = buildEntry(1L, "Broken", user, LocalDateTime.now().minusDays(5));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString()))
                .thenThrow(new RuntimeException("Key derivation failed"));

        // Should not throw, should return gracefully with empty string
        SecurityScoreResponse result = calculator.calculateSecurityScore(1L);

        assertNotNull(result);
        assertEquals(1, result.getTotalPasswords());
    }

    // ── calculatePasswordHealth ───────────────────────────────────────────────

    @Test
    void calculatePasswordHealth_VariedStrengths_ShouldReturnCorrectCounts() {
        VaultEntry strong = buildEntry(1L, "StrongEntry", user, LocalDateTime.now());
        VaultEntry weak = buildEntry(2L, "WeakEntry", user, LocalDateTime.now());
        VaultEntry fair = buildEntry(3L, "FairEntry", user, LocalDateTime.now());

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(strong, weak, fair));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey)))
                .thenReturn("Str0ng!Pass#2024")
                .thenReturn("weak")
                .thenReturn("FairPass1");
        when(passwordStrengthCalculator.calculateScore("Str0ng!Pass#2024")).thenReturn(90);
        when(passwordStrengthCalculator.calculateScore("weak")).thenReturn(20);
        when(passwordStrengthCalculator.calculateScore("FairPass1")).thenReturn(55);
        when(passwordStrengthCalculator.getStrengthLabel(90)).thenReturn("Strong");
        when(passwordStrengthCalculator.getStrengthLabel(20)).thenReturn("Weak");
        when(passwordStrengthCalculator.getStrengthLabel(55)).thenReturn("Fair");

        PasswordHealthMetricsResponse result = calculator.calculatePasswordHealth(1L);

        assertNotNull(result);
        assertEquals(3, result.getTotalPasswords());
        assertEquals(1, result.getStrongCount());
        assertEquals(1, result.getWeakCount());
        assertEquals(1, result.getFairCount());
        assertTrue(result.getAverageStrengthScore() > 0);
    }

    @Test
    void calculatePasswordHealth_EmptyVault_ShouldReturnZeros() {
        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(Collections.emptyList());

        PasswordHealthMetricsResponse result = calculator.calculatePasswordHealth(1L);

        assertNotNull(result);
        assertEquals(0, result.getTotalPasswords());
        assertEquals(0.0, result.getAverageStrengthScore());
        assertTrue(result.getCategoryBreakdowns().isEmpty());
    }

    @Test
    void calculatePasswordHealth_WithCategory_ShouldGroupByCategory() {
        Category category = Category.builder().id(1L).name("Social Media").build();

        VaultEntry entry = buildEntry(1L, "Twitter", user, LocalDateTime.now());
        entry.setCategory(category);

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("Tw!tter@2024");
        when(passwordStrengthCalculator.calculateScore("Tw!tter@2024")).thenReturn(80);
        when(passwordStrengthCalculator.getStrengthLabel(80)).thenReturn("Good");

        PasswordHealthMetricsResponse result = calculator.calculatePasswordHealth(1L);

        assertNotNull(result);
        assertEquals(1, result.getCategoryBreakdowns().size());
        assertEquals("Social Media", result.getCategoryBreakdowns().get(0).getCategoryName());
        assertEquals(1, result.getCategoryBreakdowns().get(0).getCount());
    }

    @Test
    void calculatePasswordHealth_UncategorizedEntry_ShouldGroupAsUncategorized() {
        VaultEntry entry = buildEntry(1L, "NoCategory", user, LocalDateTime.now());
        entry.setCategory(null);

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("Pass123!");
        when(passwordStrengthCalculator.calculateScore("Pass123!")).thenReturn(70);
        when(passwordStrengthCalculator.getStrengthLabel(70)).thenReturn("Good");

        PasswordHealthMetricsResponse result = calculator.calculatePasswordHealth(1L);

        assertNotNull(result);
        assertEquals(1, result.getCategoryBreakdowns().size());
        assertEquals("Uncategorized", result.getCategoryBreakdowns().get(0).getCategoryName());
    }

    // ── findReusedPasswords ───────────────────────────────────────────────────

    @Test
    void findReusedPasswords_WithReusedPasswords_ShouldReturnGroups() {
        VaultEntry entry1 = buildEntry(1L, "Gmail", user, LocalDateTime.now());
        VaultEntry entry2 = buildEntry(2L, "Yahoo", user, LocalDateTime.now());

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry1, entry2));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("SamePassword!");

        ReusedPasswordResponse result = calculator.findReusedPasswords(1L);

        assertNotNull(result);
        assertEquals(1, result.getTotalReusedGroups());
        assertEquals(2, result.getTotalAffectedEntries());
        assertEquals(2, result.getReusedGroups().get(0).getReuseCount());
    }

    @Test
    void findReusedPasswords_NoReuse_ShouldReturnEmpty() {
        VaultEntry entry1 = buildEntry(1L, "Gmail", user, LocalDateTime.now());
        VaultEntry entry2 = buildEntry(2L, "Yahoo", user, LocalDateTime.now());

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry1, entry2));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey)))
                .thenReturn("UniquePassword1!")
                .thenReturn("UniquePassword2!");

        ReusedPasswordResponse result = calculator.findReusedPasswords(1L);

        assertNotNull(result);
        assertEquals(0, result.getTotalReusedGroups());
        assertEquals(0, result.getTotalAffectedEntries());
        assertTrue(result.getReusedGroups().isEmpty());
    }

    @Test
    void findReusedPasswords_EmptyVault_ShouldReturnEmpty() {
        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(Collections.emptyList());

        ReusedPasswordResponse result = calculator.findReusedPasswords(1L);

        assertNotNull(result);
        assertEquals(0, result.getTotalReusedGroups());
        assertEquals(0, result.getTotalAffectedEntries());
    }

    @Test
    void findReusedPasswords_ThreeEntriesSamePassword_ShouldCountAll() {
        VaultEntry e1 = buildEntry(1L, "Site1", user, LocalDateTime.now());
        VaultEntry e2 = buildEntry(2L, "Site2", user, LocalDateTime.now());
        VaultEntry e3 = buildEntry(3L, "Site3", user, LocalDateTime.now());

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(e1, e2, e3));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("SharedPassword!");

        ReusedPasswordResponse result = calculator.findReusedPasswords(1L);

        assertNotNull(result);
        assertEquals(1, result.getTotalReusedGroups());
        assertEquals(3, result.getTotalAffectedEntries());
        assertEquals(3, result.getReusedGroups().get(0).getReuseCount());
    }

    // ── calculatePasswordAge ──────────────────────────────────────────────────

    @Test
    void calculatePasswordAge_FreshPasswords_ShouldCountAsFresh() {
        VaultEntry entry = buildEntry(1L, "Fresh", user, LocalDateTime.now().minusDays(10));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(entry));

        PasswordAgeResponse result = calculator.calculatePasswordAge(1L);

        assertNotNull(result);
        assertEquals(1, result.getTotalPasswords());
        assertEquals(1, result.getFreshCount());
        assertEquals(0, result.getAgingCount());
        assertEquals(0, result.getOldCount());
        assertEquals(0, result.getAncientCount());
    }

    @Test
    void calculatePasswordAge_OldPasswords_ShouldClassifyCorrectly() {
        VaultEntry fresh = buildEntry(1L, "Fresh", user, LocalDateTime.now().minusDays(5));
        VaultEntry aging = buildEntry(2L, "Aging", user, LocalDateTime.now().minusDays(60));
        VaultEntry old = buildEntry(3L, "Old", user, LocalDateTime.now().minusDays(120));
        VaultEntry ancient = buildEntry(4L, "Ancient", user, LocalDateTime.now().minusDays(200));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(fresh, aging, old, ancient));

        PasswordAgeResponse result = calculator.calculatePasswordAge(1L);

        assertNotNull(result);
        assertEquals(4, result.getTotalPasswords());
        assertEquals(1, result.getFreshCount());
        assertEquals(1, result.getAgingCount());
        assertEquals(1, result.getOldCount());
        assertEquals(1, result.getAncientCount());
    }

    @Test
    void calculatePasswordAge_EmptyVault_ShouldReturnZeros() {
        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(Collections.emptyList());

        PasswordAgeResponse result = calculator.calculatePasswordAge(1L);

        assertNotNull(result);
        assertEquals(0, result.getTotalPasswords());
        assertEquals(0, result.getFreshCount());
        assertEquals(0.0, result.getAverageAgeInDays());
        assertEquals(4, result.getDistribution().size());
    }

    @Test
    void calculatePasswordAge_AverageAge_ShouldBeCorrect() {
        VaultEntry e1 = buildEntry(1L, "E1", user, LocalDateTime.now().minusDays(10));
        VaultEntry e2 = buildEntry(2L, "E2", user, LocalDateTime.now().minusDays(20));

        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(List.of(e1, e2));

        PasswordAgeResponse result = calculator.calculatePasswordAge(1L);

        assertNotNull(result);
        // Average of 10 and 20 = 15, but clock drift means we check within a range
        assertTrue(result.getAverageAgeInDays() >= 14 && result.getAverageAgeInDays() <= 16);
    }

    @Test
    void calculatePasswordAge_DistributionBuckets_ShouldHaveFourBuckets() {
        when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L))
                .thenReturn(Collections.emptyList());

        PasswordAgeResponse result = calculator.calculatePasswordAge(1L);

        assertNotNull(result.getDistribution());
        assertEquals(4, result.getDistribution().size());
        assertEquals("< 30 days", result.getDistribution().get(0).getLabel());
        assertEquals("30-90 days", result.getDistribution().get(1).getLabel());
        assertEquals("90-180 days", result.getDistribution().get(2).getLabel());
        assertEquals("> 180 days", result.getDistribution().get(3).getLabel());
    }

    // ── computeOverallScore ───────────────────────────────────────────────────

    @Test
    void computeOverallScore_AllStrong_ShouldReturn100OrNear() {
        int score = calculator.computeOverallScore(5, 0, 0, 0);
        assertEquals(100, score);
    }

    @Test
    void computeOverallScore_AllWeak_ShouldBeVeryLow() {
        int score = calculator.computeOverallScore(5, 5, 0, 0);
        assertTrue(score <= 60);
    }

    @Test
    void computeOverallScore_EmptyVault_ShouldReturn100() {
        int score = calculator.computeOverallScore(0, 0, 0, 0);
        assertEquals(100, score);
    }

    @Test
    void computeOverallScore_NeverNegative() {
        int score = calculator.computeOverallScore(10, 10, 10, 10);
        assertTrue(score >= 0);
    }

    @Test
    void computeOverallScore_NeverAbove100() {
        int score = calculator.computeOverallScore(5, 0, 0, 0);
        assertTrue(score <= 100);
    }

    // ── getScoreLabel ─────────────────────────────────────────────────────────

    @Test
    void getScoreLabel_Excellent() {
        assertEquals("Excellent", calculator.getScoreLabel(95));
        assertEquals("Excellent", calculator.getScoreLabel(90));
    }

    @Test
    void getScoreLabel_Good() {
        assertEquals("Good", calculator.getScoreLabel(80));
        assertEquals("Good", calculator.getScoreLabel(75));
    }

    @Test
    void getScoreLabel_Fair() {
        assertEquals("Fair", calculator.getScoreLabel(60));
        assertEquals("Fair", calculator.getScoreLabel(50));
    }

    @Test
    void getScoreLabel_Poor() {
        assertEquals("Poor", calculator.getScoreLabel(30));
        assertEquals("Poor", calculator.getScoreLabel(25));
    }

    @Test
    void getScoreLabel_Critical() {
        assertEquals("Critical", calculator.getScoreLabel(10));
        assertEquals("Critical", calculator.getScoreLabel(0));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private VaultEntry buildEntry(Long id, String title, User user, LocalDateTime updatedAt) {
        return VaultEntry.builder()
                .id(id)
                .title(title)
                .username("encryptedUsername")
                .password("encryptedPassword")
                .websiteUrl("https://example.com")
                .user(user)
                .createdAt(updatedAt)
                .updatedAt(updatedAt)
                .isDeleted(false)
                .isFavorite(false)
                .isHighlySensitive(false)
                .build();
    }
}
