package com.revature.passwordmanager.service.dashboard;

import com.revature.passwordmanager.dto.response.PasswordAgeResponse;
import com.revature.passwordmanager.dto.response.PasswordHealthMetricsResponse;
import com.revature.passwordmanager.dto.response.ReusedPasswordResponse;
import com.revature.passwordmanager.dto.response.SecurityScoreResponse;
import com.revature.passwordmanager.dto.response.SecurityTrendResponse;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.dashboard.SecurityMetricsHistory;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.SecurityMetricsHistoryRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordStrengthDashboardServiceTest {

    @Mock
    private SecurityMetricsCalculator metricsCalculator;

    @Mock
    private SecurityMetricsHistoryRepository historyRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private PasswordStrengthDashboardService service;

    private User user;
    private SecurityScoreResponse sampleScore;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .masterPasswordHash("hash")
                .salt("salt")
                .build();

        sampleScore = SecurityScoreResponse.builder()
                .overallScore(82)
                .scoreLabel("Good")
                .totalPasswords(10)
                .strongPasswords(7)
                .fairPasswords(2)
                .weakPasswords(1)
                .reusedPasswords(0)
                .oldPasswords(1)
                .recommendation("Update 1 old password.")
                .build();
    }

    // ── getSecurityScore ──────────────────────────────────────────────────────

    @Test
    void getSecurityScore_ShouldReturnCalculatedScore() {
        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculateSecurityScore(1L)).thenReturn(sampleScore);
        when(historyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        SecurityScoreResponse result = service.getSecurityScore("testuser");

        assertNotNull(result);
        assertEquals(82, result.getOverallScore());
        assertEquals("Good", result.getScoreLabel());
        assertEquals(10, result.getTotalPasswords());
        verify(metricsCalculator).calculateSecurityScore(1L);
    }

    @Test
    void getSecurityScore_ShouldPersistSnapshot() {
        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculateSecurityScore(1L)).thenReturn(sampleScore);
        when(historyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.getSecurityScore("testuser");

        ArgumentCaptor<SecurityMetricsHistory> captor = ArgumentCaptor.forClass(SecurityMetricsHistory.class);
        verify(historyRepository).save(captor.capture());

        SecurityMetricsHistory saved = captor.getValue();
        assertEquals(82, saved.getOverallScore());
        assertEquals(1, saved.getWeakPasswordsCount());
        assertEquals(0, saved.getReusedPasswordsCount());
        assertEquals(1, saved.getOldPasswordsCount());
        assertEquals(user, saved.getUser());
    }

    @Test
    void getSecurityScore_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class, () -> service.getSecurityScore("unknown"));
        verify(metricsCalculator, never()).calculateSecurityScore(any());
        verify(historyRepository, never()).save(any());
    }

    @Test
    void getSecurityScore_EmptyVault_ShouldReturnPerfectScore() {
        SecurityScoreResponse emptyScore = SecurityScoreResponse.builder()
                .overallScore(100)
                .scoreLabel("Excellent")
                .totalPasswords(0)
                .recommendation("Add passwords to your vault.")
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculateSecurityScore(1L)).thenReturn(emptyScore);
        when(historyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        SecurityScoreResponse result = service.getSecurityScore("testuser");

        assertEquals(100, result.getOverallScore());
        assertEquals("Excellent", result.getScoreLabel());
    }

    // ── getPasswordHealth ─────────────────────────────────────────────────────

    @Test
    void getPasswordHealth_ShouldReturnHealthMetrics() {
        PasswordHealthMetricsResponse healthResponse = PasswordHealthMetricsResponse.builder()
                .totalPasswords(10)
                .strongCount(4)
                .goodCount(3)
                .fairCount(2)
                .weakCount(1)
                .veryWeakCount(0)
                .averageStrengthScore(68.5)
                .categoryBreakdowns(List.of())
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculatePasswordHealth(1L)).thenReturn(healthResponse);

        PasswordHealthMetricsResponse result = service.getPasswordHealth("testuser");

        assertNotNull(result);
        assertEquals(10, result.getTotalPasswords());
        assertEquals(4, result.getStrongCount());
        assertEquals(1, result.getWeakCount());
        assertEquals(68.5, result.getAverageStrengthScore());
        verify(metricsCalculator).calculatePasswordHealth(1L);
    }

    @Test
    void getPasswordHealth_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class, () -> service.getPasswordHealth("unknown"));
    }

    @Test
    void getPasswordHealth_ShouldNotPersistSnapshot() {
        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculatePasswordHealth(1L))
                .thenReturn(PasswordHealthMetricsResponse.builder().build());

        service.getPasswordHealth("testuser");

        // getPasswordHealth should NOT write to history
        verify(historyRepository, never()).save(any());
    }

    // ── getReusedPasswords ────────────────────────────────────────────────────

    @Test
    void getReusedPasswords_ShouldReturnReusedGroups() {
        ReusedPasswordResponse reusedResponse = ReusedPasswordResponse.builder()
                .totalReusedGroups(1)
                .totalAffectedEntries(2)
                .reusedGroups(List.of())
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.findReusedPasswords(1L)).thenReturn(reusedResponse);

        ReusedPasswordResponse result = service.getReusedPasswords("testuser");

        assertNotNull(result);
        assertEquals(1, result.getTotalReusedGroups());
        assertEquals(2, result.getTotalAffectedEntries());
        verify(metricsCalculator).findReusedPasswords(1L);
    }

    @Test
    void getReusedPasswords_NoReuse_ShouldReturnEmpty() {
        ReusedPasswordResponse emptyResponse = ReusedPasswordResponse.builder()
                .totalReusedGroups(0)
                .totalAffectedEntries(0)
                .reusedGroups(Collections.emptyList())
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.findReusedPasswords(1L)).thenReturn(emptyResponse);

        ReusedPasswordResponse result = service.getReusedPasswords("testuser");

        assertNotNull(result);
        assertEquals(0, result.getTotalReusedGroups());
        assertTrue(result.getReusedGroups().isEmpty());
    }

    @Test
    void getReusedPasswords_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class, () -> service.getReusedPasswords("unknown"));
    }

    // ── getPasswordAge ────────────────────────────────────────────────────────

    @Test
    void getPasswordAge_ShouldReturnAgeDistribution() {
        PasswordAgeResponse ageResponse = PasswordAgeResponse.builder()
                .totalPasswords(10)
                .freshCount(5)
                .agingCount(3)
                .oldCount(1)
                .ancientCount(1)
                .averageAgeInDays(45.0)
                .distribution(List.of())
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(metricsCalculator.calculatePasswordAge(1L)).thenReturn(ageResponse);

        PasswordAgeResponse result = service.getPasswordAge("testuser");

        assertNotNull(result);
        assertEquals(10, result.getTotalPasswords());
        assertEquals(5, result.getFreshCount());
        assertEquals(45.0, result.getAverageAgeInDays());
        verify(metricsCalculator).calculatePasswordAge(1L);
    }

    @Test
    void getPasswordAge_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class, () -> service.getPasswordAge("unknown"));
    }

    // ── getSecurityTrends ─────────────────────────────────────────────────────

    @Test
    void getSecurityTrends_ShouldReturnImprovingTrend() {
        SecurityMetricsHistory early = SecurityMetricsHistory.builder()
                .overallScore(60)
                .weakPasswordsCount(3)
                .reusedPasswordsCount(2)
                .oldPasswordsCount(1)
                .recordedAt(LocalDateTime.now().minusDays(25))
                .build();

        SecurityMetricsHistory recent = SecurityMetricsHistory.builder()
                .overallScore(80)
                .weakPasswordsCount(1)
                .reusedPasswordsCount(0)
                .oldPasswordsCount(1)
                .recordedAt(LocalDateTime.now().minusDays(5))
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(early, recent));

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 30);

        assertNotNull(result);
        assertEquals(2, result.getTrendPoints().size());
        assertEquals(20, result.getScoreChange()); // 80 - 60
        assertEquals("IMPROVING", result.getTrendDirection());
        assertEquals("30-day trend", result.getPeriodLabel());
    }

    @Test
    void getSecurityTrends_ShouldReturnDecliningTrend() {
        SecurityMetricsHistory early = SecurityMetricsHistory.builder()
                .overallScore(85)
                .weakPasswordsCount(0)
                .reusedPasswordsCount(0)
                .oldPasswordsCount(0)
                .recordedAt(LocalDateTime.now().minusDays(20))
                .build();

        SecurityMetricsHistory recent = SecurityMetricsHistory.builder()
                .overallScore(70)
                .weakPasswordsCount(2)
                .reusedPasswordsCount(1)
                .oldPasswordsCount(0)
                .recordedAt(LocalDateTime.now().minusDays(2))
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(early, recent));

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 30);

        assertNotNull(result);
        assertEquals(-15, result.getScoreChange());
        assertEquals("DECLINING", result.getTrendDirection());
    }

    @Test
    void getSecurityTrends_SingleDataPoint_ShouldBeStable() {
        SecurityMetricsHistory single = SecurityMetricsHistory.builder()
                .overallScore(75)
                .weakPasswordsCount(1)
                .reusedPasswordsCount(0)
                .oldPasswordsCount(0)
                .recordedAt(LocalDateTime.now().minusDays(1))
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(single));

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 30);

        assertNotNull(result);
        assertEquals(0, result.getScoreChange());
        assertEquals("STABLE", result.getTrendDirection());
    }

    @Test
    void getSecurityTrends_NoHistory_ShouldReturnEmptyStable() {
        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(Collections.emptyList());

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 30);

        assertNotNull(result);
        assertTrue(result.getTrendPoints().isEmpty());
        assertEquals(0, result.getScoreChange());
        assertEquals("STABLE", result.getTrendDirection());
    }

    @Test
    void getSecurityTrends_CustomDays_ShouldPassCorrectPeriodLabel() {
        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(Collections.emptyList());

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 7);

        assertEquals("7-day trend", result.getPeriodLabel());
    }

    @Test
    void getSecurityTrends_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class, () -> service.getSecurityTrends("unknown", 30));
    }

    @Test
    void getSecurityTrends_ShouldMapTrendPointsCorrectly() {
        LocalDateTime recorded = LocalDateTime.now().minusDays(5);
        SecurityMetricsHistory h = SecurityMetricsHistory.builder()
                .overallScore(78)
                .weakPasswordsCount(2)
                .reusedPasswordsCount(1)
                .oldPasswordsCount(3)
                .recordedAt(recorded)
                .build();

        when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
        when(historyRepository.findTrendData(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(h));

        SecurityTrendResponse result = service.getSecurityTrends("testuser", 30);

        SecurityTrendResponse.TrendDataPoint point = result.getTrendPoints().get(0);
        assertEquals(78, point.getOverallScore());
        assertEquals(2, point.getWeakPasswordsCount());
        assertEquals(1, point.getReusedPasswordsCount());
        assertEquals(3, point.getOldPasswordsCount());
        assertEquals(recorded, point.getRecordedAt());
    }
}
