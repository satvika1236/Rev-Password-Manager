package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.*;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.analytics.TimelinePeriod;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.model.vault.VaultSnapshot;
import com.revature.passwordmanager.repository.*;
import com.revature.passwordmanager.service.security.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core service for Feature 37: Vault Timeline Visualization.
 * <p>
 * Aggregates audit logs, vault snapshots, and share records into a chronological
 * timeline of vault activity for the authenticated user. The timeline is purely
 * read-only — it derives all data from existing records rather than maintaining
 * its own state.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class VaultTimelineService {

    private final AuditLogRepository auditLogRepository;
    private final VaultEntryRepository vaultEntryRepository;
    private final VaultSnapshotRepository vaultSnapshotRepository;
    private final SecureShareRepository secureShareRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final ActivityAggregator activityAggregator;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter MONTH_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM");

    /** Valid category filter values accepted by the timeline endpoint. */
    private static final Set<String> VALID_CATEGORIES =
            Set.of("VAULT", "AUTH", "BREACH", "SHARING", "BACKUP", "SECURITY");

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Returns the full vault timeline for the authenticated user,
     * optionally filtered by time range and event category.
     *
     * @param username     the authenticated user
     * @param days         how many days back to fetch (0 or null = all time)
     * @param categoryFilter optional event category filter (VAULT, AUTH, BREACH, SHARING, BACKUP, SECURITY)
     * @return paginated timeline response with category breakdown
     */
    @Transactional(readOnly = true)
    public VaultTimelineResponse getTimeline(String username, Integer days, String categoryFilter) {
        // Fix: validate category filter — return 400 for unknown values instead of silently empty list
        if (categoryFilter != null && !categoryFilter.isBlank()
                && !VALID_CATEGORIES.contains(categoryFilter.toUpperCase())) {
            throw new IllegalArgumentException(
                    "Invalid category filter '" + categoryFilter + "'. Valid values: " + VALID_CATEGORIES);
        }

        User user = userRepository.findByUsernameOrThrow(username);
        List<AuditLog> logs = fetchLogs(user.getId(), days);

        // Audit log the timeline access (after fetching so it doesn't include itself)
        auditLogService.logAction(username, AuditAction.TIMELINE_VIEWED, "Viewed vault timeline");

        List<TimelineEventDTO> events = activityAggregator.aggregate(logs, user.getId());

        // Apply category filter if provided (now guaranteed to be a valid value)
        if (categoryFilter != null && !categoryFilter.isBlank()) {
            final String upperCategory = categoryFilter.toUpperCase();
            events = events.stream()
                    .filter(e -> upperCategory.equalsIgnoreCase(e.getCategory()))
                    .collect(Collectors.toList());
        }

        VaultTimelineResponse.CategoryBreakdown breakdown = computeCategoryBreakdown(events);

        // Use TimelinePeriod to compute accurate period label, start, and end dates
        LocalDateTime earliest = logs.isEmpty() ? null
                : logs.get(logs.size() - 1).getTimestamp();
        TimelinePeriod period = TimelinePeriod.resolve(days, earliest);

        return VaultTimelineResponse.builder()
                .events(events)
                .totalEvents(events.size())
                .period(period.getLabel())
                .startDate(period.getStart().format(DATE_FORMATTER))
                .endDate(period.getEnd().format(DATE_FORMATTER))
                .categoryBreakdown(breakdown)
                .build();
    }

    /**
     * Returns a high-level activity summary for the user's vault.
     *
     * @param username the authenticated user
     * @return summary statistics and most-accessed entries
     */
    @Transactional(readOnly = true)
    public TimelineSummaryResponse getSummary(String username) {
        User user = userRepository.findByUsernameOrThrow(username);
        Long userId = user.getId();
        auditLogService.logAction(username, AuditAction.TIMELINE_VIEWED, "Viewed timeline summary");

        List<AuditLog> allLogs = auditLogRepository.findByUserIdOrderByTimestampDesc(userId);
        List<VaultSnapshot> snapshots = vaultSnapshotRepository.findByVaultEntryUserIdOrderByChangedAtDesc(userId);

        int totalCreated = countByAction(allLogs, AuditAction.ENTRY_CREATED);
        int totalDeleted = countByAction(allLogs, AuditAction.ENTRY_DELETED);
        int totalPasswordChanges = snapshots.size();
        int totalSharesCreated = countByAction(allLogs, AuditAction.SHARE_CREATED);
        int totalBreachDetections = countByAction(allLogs, AuditAction.BREACH_DETECTED);
        int totalAuditEvents = allLogs.size();

        String mostActiveDayOfWeek = computeMostActiveDayOfWeek(allLogs);
        Integer mostActiveHour = computeMostActiveHour(allLogs);

        List<TimelineSummaryResponse.EntryActivitySummary> mostAccessed =
                computeMostAccessedEntries(allLogs, userId);

        List<TimelineSummaryResponse.WeeklyActivityBucket> weeklyActivity =
                computeWeeklyActivity(allLogs);

        return TimelineSummaryResponse.builder()
                .totalEntriesCreated(totalCreated)
                .totalPasswordChanges(totalPasswordChanges)
                .totalEntriesDeleted(totalDeleted)
                .totalSharesCreated(totalSharesCreated)
                .totalBreachDetections(totalBreachDetections)
                .totalAuditEvents(totalAuditEvents)
                .mostActiveDayOfWeek(mostActiveDayOfWeek)
                .mostActiveHour(mostActiveHour)
                .mostAccessedEntries(mostAccessed)
                .weeklyActivity(weeklyActivity)
                .build();
    }

    /**
     * Returns the timeline scoped to a single vault entry — showing its full lifecycle.
     * The entry must belong to the authenticated user (checks ownership).
     *
     * @param username the authenticated user
     * @param entryId  the vault entry id
     * @return per-entry timeline response
     */
    @Transactional(readOnly = true)
    public EntryTimelineResponse getEntryTimeline(String username, Long entryId) {
        User user = userRepository.findByUsernameOrThrow(username);

        auditLogService.logAction(username, AuditAction.TIMELINE_VIEWED,
                "Viewed timeline for entry id=" + entryId);

        // Security: verify the entry belongs to the authenticated user
        VaultEntry entry = vaultEntryRepository.findByIdAndUserId(entryId, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Vault entry not found: " + entryId));

        // Fetch all audit logs that reference this entry in their details (matched by title)
        List<AuditLog> allUserLogs = auditLogRepository.findByUserIdOrderByTimestampDesc(user.getId());
        String entryTitle = entry.getTitle();
        List<AuditLog> entryLogs = allUserLogs.stream()
                .filter(log -> isLogForEntry(log, entryId, entryTitle))
                .collect(Collectors.toList());

        List<TimelineEventDTO> events = activityAggregator.aggregate(entryLogs, user.getId());

        // Also count snapshots for this entry (password changes)
        List<VaultSnapshot> snapshots = vaultSnapshotRepository.findByVaultEntryIdOrderByChangedAtDesc(entryId);
        int passwordChanges = snapshots.size();

        int passwordViews = countByAction(entryLogs, AuditAction.PASSWORD_VIEWED);
        int shareCount = (int) secureShareRepository.findByOwnerIdOrderByCreatedAtDesc(user.getId())
                .stream()
                .filter(s -> s.getVaultEntry() != null && entryId.equals(s.getVaultEntry().getId()))
                .count();

        return EntryTimelineResponse.builder()
                .entryId(entryId)
                .entryTitle(entry.getTitle())
                .websiteUrl(entry.getWebsiteUrl())
                .deleted(Boolean.TRUE.equals(entry.getIsDeleted()))
                .events(events)
                .passwordChangeCount(passwordChanges)
                .passwordViewCount(passwordViews)
                .shareCount(shareCount)
                .build();
    }

    /**
     * Returns aggregated activity statistics suited for chart rendering.
     *
     * @param username the authenticated user
     * @param days     number of days to include in the stats (0 = all time)
     * @return statistics response with daily/monthly breakdowns and event type counts
     */
    @Transactional(readOnly = true)
    public TimelineStatsResponse getStats(String username, Integer days) {
        User user = userRepository.findByUsernameOrThrow(username);
        Long userId = user.getId();
        auditLogService.logAction(username, AuditAction.TIMELINE_VIEWED, "Viewed timeline stats");

        List<AuditLog> logs = fetchLogs(userId, days);
        List<TimelineEventDTO> events = activityAggregator.aggregate(logs, userId);

        Map<String, Integer> byType = new LinkedHashMap<>();
        Map<String, Integer> byCategory = new LinkedHashMap<>();

        for (TimelineEventDTO e : events) {
            byType.merge(e.getEventType(), 1, Integer::sum);
            byCategory.merge(e.getCategory(), 1, Integer::sum);
        }

        List<TimelineStatsResponse.DailyActivityBucket> dailyActivity = buildDailyBuckets(events);
        List<TimelineStatsResponse.MonthlyActivityBucket> monthlyActivity = buildMonthlyBuckets(events);

        int total = events.size();
        double avgPerDay = computeAvgPerDay(events, days);
        String peakDate = findPeakDate(dailyActivity);
        int peakCount = dailyActivity.stream()
                .mapToInt(TimelineStatsResponse.DailyActivityBucket::getCount)
                .max().orElse(0);

        return TimelineStatsResponse.builder()
                .eventsByType(byType)
                .eventsByCategory(byCategory)
                .dailyActivity(dailyActivity)
                .monthlyActivity(monthlyActivity)
                .totalEvents(total)
                .averageEventsPerDay(avgPerDay)
                .peakActivityDate(peakDate)
                .peakActivityCount(peakCount)
                .build();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private List<AuditLog> fetchLogs(Long userId, Integer days) {
        if (days == null || days <= 0) {
            return auditLogRepository.findByUserIdOrderByTimestampDesc(userId);
        }
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return auditLogRepository.findByUserIdAndTimestampAfter(userId, since);
    }

    private int countByAction(List<AuditLog> logs, AuditAction action) {
        return (int) logs.stream().filter(l -> l.getAction() == action).count();
    }

    private VaultTimelineResponse.CategoryBreakdown computeCategoryBreakdown(List<TimelineEventDTO> events) {
        int vault = 0, security = 0, sharing = 0, auth = 0, breach = 0, backup = 0;
        for (TimelineEventDTO e : events) {
            switch (e.getCategory()) {
                case "VAULT" -> vault++;
                case "SECURITY" -> security++;
                case "SHARING" -> sharing++;
                case "AUTH" -> auth++;
                case "BREACH" -> breach++;
                case "BACKUP" -> backup++;
            }
        }
        return VaultTimelineResponse.CategoryBreakdown.builder()
                .vaultEvents(vault)
                .securityEvents(security)
                .sharingEvents(sharing)
                .authEvents(auth)
                .breachEvents(breach)
                .backupEvents(backup)
                .build();
    }

    private String deriveStartDate(List<AuditLog> logs) {
        return logs.isEmpty()
                ? LocalDateTime.now().format(DATE_FORMATTER)
                : logs.get(logs.size() - 1).getTimestamp().format(DATE_FORMATTER);
    }

    private String computeMostActiveDayOfWeek(List<AuditLog> logs) {
        // Fix: return null for empty log sets instead of defaulting to "Sunday"
        if (logs.isEmpty()) return null;
        int[] counts = new int[7];
        for (AuditLog log : logs) {
            int dayIdx = log.getTimestamp().getDayOfWeek().getValue() % 7; // 0=Sun
            counts[dayIdx]++;
        }
        int maxIdx = 0;
        for (int i = 1; i < 7; i++) {
            if (counts[i] > counts[maxIdx]) maxIdx = i;
        }
        // Convert back: index 0 = Sunday (ISO Sunday = 7, getValue()%7 = 0)
        int javaDayVal = maxIdx == 0 ? 7 : maxIdx;
        return DayOfWeek.of(javaDayVal).getDisplayName(TextStyle.FULL, Locale.getDefault());
    }

    private Integer computeMostActiveHour(List<AuditLog> logs) {
        // Fix: return null for empty log sets instead of defaulting to midnight (0)
        if (logs.isEmpty()) return null;
        int[] counts = new int[24];
        for (AuditLog log : logs) {
            counts[log.getTimestamp().getHour()]++;
        }
        int maxHour = 0;
        for (int i = 1; i < 24; i++) {
            if (counts[i] > counts[maxHour]) maxHour = i;
        }
        return maxHour;
    }

    private List<TimelineSummaryResponse.EntryActivitySummary> computeMostAccessedEntries(
            List<AuditLog> allLogs, Long userId) {

        // Count PASSWORD_VIEWED + ENTRY_UPDATED events per entry title extracted from details
        Map<String, Integer> titleAccessCounts = new LinkedHashMap<>();
        for (AuditLog log : allLogs) {
            if (log.getAction() == AuditAction.PASSWORD_VIEWED || log.getAction() == AuditAction.ENTRY_UPDATED) {
                String title = activityAggregator.extractEntryTitle(log.getDetails(), log.getAction());
                if (title != null) {
                    titleAccessCounts.merge(title, 1, Integer::sum);
                }
            }
        }

        // Resolve titles -> entries via the title cache for id/websiteUrl
        Map<String, VaultEntry> titleCache = activityAggregator.buildTitleCache(userId);

        return titleAccessCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(5)
                .map(e -> {
                    VaultEntry entry = titleCache.get(e.getKey().toLowerCase());
                    return TimelineSummaryResponse.EntryActivitySummary.builder()
                            .entryId(entry != null ? entry.getId() : null)
                            .entryTitle(e.getKey())
                            .websiteUrl(entry != null ? entry.getWebsiteUrl() : null)
                            .accessCount(e.getValue())
                            .build();
                })
                .collect(Collectors.toList());
    }

    private List<TimelineSummaryResponse.WeeklyActivityBucket> computeWeeklyActivity(List<AuditLog> allLogs) {
        // Build buckets for last 12 weeks
        LocalDate today = LocalDate.now();
        LocalDate startOfWindow = today.minusWeeks(12);

        Map<LocalDate, Integer> weekBuckets = new LinkedHashMap<>();
        // Initialize all 12 weekly buckets (week starting Monday)
        for (int w = 11; w >= 0; w--) {
            LocalDate weekStart = today.minusWeeks(w).with(DayOfWeek.MONDAY);
            weekBuckets.put(weekStart, 0);
        }

        for (AuditLog log : allLogs) {
            LocalDate logDate = log.getTimestamp().toLocalDate();
            if (!logDate.isBefore(startOfWindow)) {
                LocalDate weekStart = logDate.with(DayOfWeek.MONDAY);
                weekBuckets.merge(weekStart, 1, Integer::sum);
            }
        }

        return weekBuckets.entrySet().stream()
                .map(e -> TimelineSummaryResponse.WeeklyActivityBucket.builder()
                        .weekStart(e.getKey().format(DATE_FORMATTER))
                        .eventCount(e.getValue())
                        .build())
                .collect(Collectors.toList());
    }

    private boolean isLogForEntry(AuditLog log, Long entryId, String entryTitle) {
        AuditAction action = log.getAction();
        // Only include vault and sharing actions that reference entries
        if (action != AuditAction.ENTRY_CREATED && action != AuditAction.ENTRY_UPDATED
                && action != AuditAction.ENTRY_DELETED && action != AuditAction.ENTRY_RESTORED
                && action != AuditAction.PASSWORD_VIEWED && action != AuditAction.SHARE_CREATED
                && action != AuditAction.SHARE_REVOKED && action != AuditAction.BREACH_DETECTED
                && action != AuditAction.BREACH_RESOLVED) {
            return false;
        }
        // Match by entry title extracted from details
        String extractedTitle = activityAggregator.extractEntryTitle(log.getDetails(), action);
        return extractedTitle != null && extractedTitle.equalsIgnoreCase(entryTitle);
    }

    private List<TimelineStatsResponse.DailyActivityBucket> buildDailyBuckets(
            List<TimelineEventDTO> events) {
        Map<LocalDate, TimelineStatsResponse.DailyActivityBucket> buckets = new TreeMap<>();
        for (TimelineEventDTO event : events) {
            LocalDate date = event.getTimestamp().toLocalDate();
            buckets.computeIfAbsent(date, d -> TimelineStatsResponse.DailyActivityBucket.builder()
                    .date(d.format(DATE_FORMATTER))
                    .count(0).vaultCount(0).securityCount(0)
                    .sharingCount(0).authCount(0).backupCount(0).breachCount(0)
                    .build());
            TimelineStatsResponse.DailyActivityBucket bucket = buckets.get(date);
            bucket.setCount(bucket.getCount() + 1);
            // Fix: BACKUP and BREACH now have dedicated counters; no events are silently dropped
            switch (event.getCategory()) {
                case "VAULT"    -> bucket.setVaultCount(bucket.getVaultCount() + 1);
                case "SECURITY" -> bucket.setSecurityCount(bucket.getSecurityCount() + 1);
                case "BREACH"   -> bucket.setBreachCount(bucket.getBreachCount() + 1);
                case "SHARING"  -> bucket.setSharingCount(bucket.getSharingCount() + 1);
                case "AUTH"     -> bucket.setAuthCount(bucket.getAuthCount() + 1);
                case "BACKUP"   -> bucket.setBackupCount(bucket.getBackupCount() + 1);
            }
        }
        return new ArrayList<>(buckets.values());
    }

    private List<TimelineStatsResponse.MonthlyActivityBucket> buildMonthlyBuckets(
            List<TimelineEventDTO> events) {
        Map<String, Integer> buckets = new TreeMap<>();
        for (TimelineEventDTO event : events) {
            String month = event.getTimestamp().format(MONTH_FORMATTER);
            buckets.merge(month, 1, Integer::sum);
        }
        return buckets.entrySet().stream()
                .map(e -> TimelineStatsResponse.MonthlyActivityBucket.builder()
                        .month(e.getKey())
                        .count(e.getValue())
                        .build())
                .collect(Collectors.toList());
    }

    private double computeAvgPerDay(List<TimelineEventDTO> events, Integer days) {
        if (events.isEmpty()) return 0.0;
        long effectiveDays;
        if (days != null && days > 0) {
            effectiveDays = days;
        } else {
            // Fix: compute actual span from the oldest to newest event instead of hardcoded 365
            LocalDateTime oldest = events.stream()
                    .map(TimelineEventDTO::getTimestamp)
                    .min(Comparator.naturalOrder())
                    .orElse(LocalDateTime.now());
            effectiveDays = java.time.temporal.ChronoUnit.DAYS.between(oldest, LocalDateTime.now()) + 1;
            if (effectiveDays <= 0) effectiveDays = 1;
        }
        return Math.round((double) events.size() / effectiveDays * 100.0) / 100.0;
    }

    private String findPeakDate(List<TimelineStatsResponse.DailyActivityBucket> dailyBuckets) {
        return dailyBuckets.stream()
                .max(Comparator.comparingInt(TimelineStatsResponse.DailyActivityBucket::getCount))
                .map(TimelineStatsResponse.DailyActivityBucket::getDate)
                .orElse(null);
    }
}
