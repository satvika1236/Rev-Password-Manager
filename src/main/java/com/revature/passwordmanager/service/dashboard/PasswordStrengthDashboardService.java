package com.revature.passwordmanager.service.dashboard;

import com.revature.passwordmanager.dto.response.PasswordAgeResponse;
import com.revature.passwordmanager.dto.response.PasswordHealthMetricsResponse;
import com.revature.passwordmanager.dto.response.ReusedPasswordResponse;
import com.revature.passwordmanager.dto.response.SecurityScoreResponse;
import com.revature.passwordmanager.dto.response.SecurityTrendResponse;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.dashboard.SecurityMetricsHistory;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.SecurityMetricsHistoryRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasswordStrengthDashboardService {

    private final SecurityMetricsCalculator metricsCalculator;
    private final SecurityMetricsHistoryRepository historyRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    /**
     * Returns the overall security score (0-100) for the authenticated user
     * and persists a snapshot for trend tracking.
     */
    /** Minimum gap between snapshot persists to avoid unbounded table growth. */
    private static final long SNAPSHOT_COOLDOWN_MINUTES = 60;

    @Transactional
    public SecurityScoreResponse getSecurityScore(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        SecurityScoreResponse response = metricsCalculator.calculateSecurityScore(user.getId());
        // Gap 2 fix: only persist a snapshot if no snapshot exists within the last
        // hour.
        persistSnapshotIfCooldownElapsed(user, response);
        // Gap 4 fix: audit log dashboard access
        auditLogService.logAction(username, AuditAction.DASHBOARD_VIEWED, "Viewed security score dashboard");
        return response;
    }

    /**
     * Returns a breakdown of all vault passwords by strength category,
     * including per-category analysis.
     */
    @Transactional
    public PasswordHealthMetricsResponse getPasswordHealth(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        auditLogService.logAction(username, AuditAction.DASHBOARD_VIEWED, "Viewed password health metrics");
        return metricsCalculator.calculatePasswordHealth(user.getId());
    }

    /**
     * Returns all groups of reused passwords (same password used for multiple
     * entries).
     */
    @Transactional
    public ReusedPasswordResponse getReusedPasswords(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        auditLogService.logAction(username, AuditAction.DASHBOARD_VIEWED, "Viewed reused passwords report");
        return metricsCalculator.findReusedPasswords(user.getId());
    }

    /**
     * Returns the age distribution of all vault passwords.
     */
    @Transactional
    public PasswordAgeResponse getPasswordAge(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        auditLogService.logAction(username, AuditAction.DASHBOARD_VIEWED, "Viewed password age distribution");
        return metricsCalculator.calculatePasswordAge(user.getId());
    }

    /**
     * Returns historical security score trend data for the past N days.
     *
     * @param username the authenticated user
     * @param days     how many days back to fetch (default 30)
     */
    @Transactional(readOnly = true)
    public SecurityTrendResponse getSecurityTrends(String username, int days) {
        User user = userRepository.findByUsernameOrThrow(username);

        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<SecurityMetricsHistory> history = historyRepository.findTrendData(user.getId(), since);

        List<SecurityTrendResponse.TrendDataPoint> points = history.stream()
                .map(h -> SecurityTrendResponse.TrendDataPoint.builder()
                        .recordedAt(h.getRecordedAt())
                        .overallScore(h.getOverallScore())
                        .weakPasswordsCount(h.getWeakPasswordsCount())
                        .reusedPasswordsCount(h.getReusedPasswordsCount())
                        .oldPasswordsCount(h.getOldPasswordsCount())
                        .build())
                .collect(Collectors.toList());

        int scoreChange = computeScoreChange(points);
        String direction = scoreChange > 0 ? "IMPROVING" : scoreChange < 0 ? "DECLINING" : "STABLE";

        return SecurityTrendResponse.builder()
                .trendPoints(points)
                .scoreChange(scoreChange)
                .trendDirection(direction)
                .periodLabel(days + "-day trend")
                .build();
    }

    /**
     * Returns a list of all vault entries with weak passwords.
     */
    @Transactional(readOnly = true)
    public List<com.revature.passwordmanager.dto.response.VaultEntryResponse> getWeakPasswordsList(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        return metricsCalculator.getWeakPasswordsList(user.getId());
    }

    /**
     * Returns a list of all vault entries that have not been updated in >90 days.
     */
    @Transactional(readOnly = true)
    public List<com.revature.passwordmanager.dto.response.VaultEntryResponse> getOldPasswordsList(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        return metricsCalculator.getOldPasswordsList(user.getId());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void persistSnapshotIfCooldownElapsed(User user, SecurityScoreResponse score) {
        LocalDateTime cooldownThreshold = LocalDateTime.now().minusMinutes(SNAPSHOT_COOLDOWN_MINUTES);
        boolean recentSnapshotExists = historyRepository
                .findTopByUserIdOrderByRecordedAtDesc(user.getId())
                .map(latest -> latest.getRecordedAt().isAfter(cooldownThreshold))
                .orElse(false);

        if (!recentSnapshotExists) {
            SecurityMetricsHistory snapshot = SecurityMetricsHistory.builder()
                    .user(user)
                    .overallScore(score.getOverallScore())
                    .weakPasswordsCount(score.getWeakPasswords())
                    .reusedPasswordsCount(score.getReusedPasswords())
                    .oldPasswordsCount(score.getOldPasswords())
                    .strongPasswordsCount(score.getStrongPasswords())
                    .fairPasswordsCount(score.getFairPasswords())
                    .totalPasswordsCount(score.getTotalPasswords())
                    .build();
            historyRepository.save(snapshot);
        }
    }

    private int computeScoreChange(List<SecurityTrendResponse.TrendDataPoint> points) {
        if (points.size() < 2)
            return 0;
        int first = points.get(0).getOverallScore();
        int last = points.get(points.size() - 1).getOverallScore();
        return last - first;
    }
}
