package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.*;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.sharing.SecureShare;
import com.revature.passwordmanager.model.sharing.SharePermission;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.model.vault.VaultSnapshot;
import com.revature.passwordmanager.repository.*;
import com.revature.passwordmanager.service.security.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultTimelineServiceTest {

    @Mock private AuditLogRepository auditLogRepository;
    @Mock private VaultEntryRepository vaultEntryRepository;
    @Mock private VaultSnapshotRepository vaultSnapshotRepository;
    @Mock private SecureShareRepository secureShareRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditLogService auditLogService;
    @Mock private ActivityAggregator activityAggregator;

    @InjectMocks
    private VaultTimelineService service;

    private User alice;
    private VaultEntry netflixEntry;
    private AuditLog loginLog;
    private AuditLog createLog;
    private TimelineEventDTO loginEvent;
    private TimelineEventDTO createEvent;

    @BeforeEach
    void setUp() {
        alice = User.builder().id(1L).username("alice").build();

        netflixEntry = VaultEntry.builder()
                .id(10L).title("Netflix").websiteUrl("https://netflix.com")
                .user(alice).isDeleted(false)
                .createdAt(LocalDateTime.now().minusDays(5))
                .updatedAt(LocalDateTime.now().minusDays(1))
                .build();

        loginLog = AuditLog.builder().id(1L).user(alice).action(AuditAction.LOGIN)
                .details("Successful login").timestamp(LocalDateTime.now().minusDays(2)).build();

        createLog = AuditLog.builder().id(2L).user(alice).action(AuditAction.ENTRY_CREATED)
                .details("Created entry: Netflix").timestamp(LocalDateTime.now().minusDays(5)).build();

        loginEvent = TimelineEventDTO.builder().id(1L).eventType("LOGIN").category("AUTH")
                .severity("LOW").timestamp(loginLog.getTimestamp()).description("Successful login").build();

        createEvent = TimelineEventDTO.builder().id(2L).eventType("ENTRY_CREATED").category("VAULT")
                .severity("LOW").vaultEntryTitle("Netflix").vaultEntryId(10L)
                .timestamp(createLog.getTimestamp()).description("Created entry: Netflix").build();
    }

    // ── getTimeline ───────────────────────────────────────────────────────────

    @Test
    void getTimeline_NoFilter_ShouldReturnAllEvents() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L))
                .thenReturn(List.of(loginLog, createLog));
        when(activityAggregator.aggregate(anyList(), eq(1L)))
                .thenReturn(List.of(loginEvent, createEvent));

        VaultTimelineResponse response = service.getTimeline("alice", null, null);

        assertThat(response.getEvents()).hasSize(2);
        assertThat(response.getTotalEvents()).isEqualTo(2);
        assertThat(response.getPeriod()).isEqualTo("ALL_TIME");
        assertThat(response.getCategoryBreakdown()).isNotNull();
        assertThat(response.getCategoryBreakdown().getVaultEvents()).isEqualTo(1);
        assertThat(response.getCategoryBreakdown().getAuthEvents()).isEqualTo(1);

        verify(auditLogService).logAction(eq("alice"), eq(AuditAction.TIMELINE_VIEWED), anyString());
    }

    @Test
    void getTimeline_WithDaysFilter_ShouldFetchFromRepository() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(loginLog));
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(List.of(loginEvent));

        VaultTimelineResponse response = service.getTimeline("alice", 30, null);

        assertThat(response.getPeriod()).isEqualTo("LAST_30_DAYS");
        verify(auditLogRepository).findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class));
        verify(auditLogRepository, never()).findByUserIdOrderByTimestampDesc(anyLong());
    }

    @Test
    void getTimeline_WithCategoryFilter_ShouldFilterEvents() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L))
                .thenReturn(List.of(loginLog, createLog));
        when(activityAggregator.aggregate(anyList(), eq(1L)))
                .thenReturn(List.of(loginEvent, createEvent));

        VaultTimelineResponse response = service.getTimeline("alice", null, "AUTH");

        assertThat(response.getEvents()).hasSize(1);
        assertThat(response.getEvents().get(0).getCategory()).isEqualTo("AUTH");
    }

    @Test
    void getTimeline_EmptyVault_ShouldReturnEmptyTimeline() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(Collections.emptyList());
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(Collections.emptyList());

        VaultTimelineResponse response = service.getTimeline("alice", null, null);

        assertThat(response.getEvents()).isEmpty();
        assertThat(response.getTotalEvents()).isZero();
    }

    @Test
    void getTimeline_CategoryBreakdown_ShouldCountCorrectly() {
        TimelineEventDTO sharingEvent = TimelineEventDTO.builder().id(3L).eventType("SHARE_CREATED")
                .category("SHARING").severity("HIGH").timestamp(LocalDateTime.now()).build();
        TimelineEventDTO breachEvent = TimelineEventDTO.builder().id(4L).eventType("BREACH_DETECTED")
                .category("BREACH").severity("CRITICAL").timestamp(LocalDateTime.now()).build();

        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(List.of(loginLog));
        when(activityAggregator.aggregate(anyList(), eq(1L)))
                .thenReturn(List.of(loginEvent, createEvent, sharingEvent, breachEvent));

        VaultTimelineResponse response = service.getTimeline("alice", null, null);

        VaultTimelineResponse.CategoryBreakdown breakdown = response.getCategoryBreakdown();
        assertThat(breakdown.getAuthEvents()).isEqualTo(1);
        assertThat(breakdown.getVaultEvents()).isEqualTo(1);
        assertThat(breakdown.getSharingEvents()).isEqualTo(1);
        assertThat(breakdown.getBreachEvents()).isEqualTo(1);
    }

    // ── getSummary ────────────────────────────────────────────────────────────

    @Test
    void getSummary_ShouldReturnCorrectCounts() {
        AuditLog deleteLog = AuditLog.builder().id(3L).user(alice).action(AuditAction.ENTRY_DELETED)
                .details("Deleted entry: Netflix").timestamp(LocalDateTime.now()).build();
        AuditLog shareLog = AuditLog.builder().id(4L).user(alice).action(AuditAction.SHARE_CREATED)
                .details("Shared entry 'Netflix' token=tok").timestamp(LocalDateTime.now()).build();
        AuditLog breachLog = AuditLog.builder().id(5L).user(alice).action(AuditAction.BREACH_DETECTED)
                .details("Breach found").timestamp(LocalDateTime.now()).build();

        List<AuditLog> allLogs = List.of(createLog, deleteLog, shareLog, breachLog, loginLog);
        List<VaultSnapshot> snapshots = List.of(
                VaultSnapshot.builder().id(1L).vaultEntry(netflixEntry)
                        .password("enc").changedAt(LocalDateTime.now()).build());

        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(allLogs);
        when(vaultSnapshotRepository.findByVaultEntryUserIdOrderByChangedAtDesc(1L)).thenReturn(snapshots);
        // getSummary calls extractEntryTitle only for PASSWORD_VIEWED and ENTRY_UPDATED logs;
        // none of our test logs match those actions so no stub is needed — just stub buildTitleCache
        when(activityAggregator.buildTitleCache(1L)).thenReturn(Map.of());

        TimelineSummaryResponse summary = service.getSummary("alice");

        assertThat(summary.getTotalEntriesCreated()).isEqualTo(1);
        assertThat(summary.getTotalEntriesDeleted()).isEqualTo(1);
        assertThat(summary.getTotalSharesCreated()).isEqualTo(1);
        assertThat(summary.getTotalBreachDetections()).isEqualTo(1);
        assertThat(summary.getTotalPasswordChanges()).isEqualTo(1);
        assertThat(summary.getTotalAuditEvents()).isEqualTo(5);
    }

    @Test
    void getSummary_WeeklyActivity_ShouldReturn12Buckets() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(Collections.emptyList());
        when(vaultSnapshotRepository.findByVaultEntryUserIdOrderByChangedAtDesc(1L))
                .thenReturn(Collections.emptyList());
        when(activityAggregator.buildTitleCache(1L)).thenReturn(Map.of());

        TimelineSummaryResponse summary = service.getSummary("alice");

        assertThat(summary.getWeeklyActivity()).hasSize(12);
    }

    // ── getEntryTimeline ──────────────────────────────────────────────────────

    @Test
    void getEntryTimeline_ValidEntry_ShouldReturnEntryEvents() {
        VaultSnapshot snapshot = VaultSnapshot.builder().id(1L).vaultEntry(netflixEntry)
                .password("enc").changedAt(LocalDateTime.now()).build();
        SecureShare share = SecureShare.builder().id(1L).vaultEntry(netflixEntry).owner(alice)
                .shareToken("tok").encryptedPassword("enc").encryptionIv("iv")
                .expiresAt(LocalDateTime.now().plusHours(24)).permission(SharePermission.VIEW_ONCE)
                .build();

        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(vaultEntryRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(netflixEntry));
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(List.of(createLog, loginLog));
        // isLogForEntry checks vault/sharing actions only — loginLog.action=LOGIN is skipped before
        // extractEntryTitle is called, so we only need to stub the ENTRY_CREATED call
        when(activityAggregator.extractEntryTitle(eq("Created entry: Netflix"), eq(AuditAction.ENTRY_CREATED)))
                .thenReturn("Netflix");
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(List.of(createEvent));
        when(vaultSnapshotRepository.findByVaultEntryIdOrderByChangedAtDesc(10L))
                .thenReturn(List.of(snapshot));
        when(secureShareRepository.findByOwnerIdOrderByCreatedAtDesc(1L)).thenReturn(List.of(share));

        EntryTimelineResponse response = service.getEntryTimeline("alice", 10L);

        assertThat(response.getEntryId()).isEqualTo(10L);
        assertThat(response.getEntryTitle()).isEqualTo("Netflix");
        assertThat(response.getWebsiteUrl()).isEqualTo("https://netflix.com");
        assertThat(response.isDeleted()).isFalse();
        assertThat(response.getEvents()).hasSize(1);
        assertThat(response.getPasswordChangeCount()).isEqualTo(1);
        assertThat(response.getShareCount()).isEqualTo(1);
    }

    @Test
    void getEntryTimeline_EntryNotFound_ShouldThrow404() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(vaultEntryRepository.findByIdAndUserId(999L, 1L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getEntryTimeline("alice", 999L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void getEntryTimeline_DeletedEntry_ShouldReturnDeletedFlag() {
        VaultEntry deletedEntry = VaultEntry.builder()
                .id(10L).title("Netflix").user(alice).isDeleted(true)
                .deletedAt(LocalDateTime.now()).build();

        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(vaultEntryRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(deletedEntry));
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(Collections.emptyList());
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(Collections.emptyList());
        when(vaultSnapshotRepository.findByVaultEntryIdOrderByChangedAtDesc(10L))
                .thenReturn(Collections.emptyList());
        when(secureShareRepository.findByOwnerIdOrderByCreatedAtDesc(1L)).thenReturn(Collections.emptyList());

        EntryTimelineResponse response = service.getEntryTimeline("alice", 10L);

        assertThat(response.isDeleted()).isTrue();
    }

    // ── getStats ──────────────────────────────────────────────────────────────

    @Test
    void getStats_ShouldReturnEventsByTypeAndCategory() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L))
                .thenReturn(List.of(loginLog, createLog));
        when(activityAggregator.aggregate(anyList(), eq(1L)))
                .thenReturn(List.of(loginEvent, createEvent));

        TimelineStatsResponse stats = service.getStats("alice", null);

        assertThat(stats.getEventsByType()).containsKey("LOGIN");
        assertThat(stats.getEventsByType()).containsKey("ENTRY_CREATED");
        assertThat(stats.getEventsByType().get("LOGIN")).isEqualTo(1);
        assertThat(stats.getEventsByCategory()).containsKey("AUTH");
        assertThat(stats.getEventsByCategory()).containsKey("VAULT");
        assertThat(stats.getTotalEvents()).isEqualTo(2);
    }

    @Test
    void getStats_ShouldReturnDailyBuckets() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L))
                .thenReturn(List.of(loginLog, createLog));
        when(activityAggregator.aggregate(anyList(), eq(1L)))
                .thenReturn(List.of(loginEvent, createEvent));

        TimelineStatsResponse stats = service.getStats("alice", null);

        assertThat(stats.getDailyActivity()).isNotEmpty();
        assertThat(stats.getMonthlyActivity()).isNotEmpty();
    }

    @Test
    void getStats_WithDaysParam_ShouldUseFilteredLogs() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class)))
                .thenReturn(List.of(loginLog));
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(List.of(loginEvent));

        TimelineStatsResponse stats = service.getStats("alice", 7);

        assertThat(stats.getTotalEvents()).isEqualTo(1);
        verify(auditLogRepository).findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class));
    }

    @Test
    void getStats_EmptyVault_ShouldReturnZeroMetrics() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(alice);
        when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L)).thenReturn(Collections.emptyList());
        when(activityAggregator.aggregate(anyList(), eq(1L))).thenReturn(Collections.emptyList());

        TimelineStatsResponse stats = service.getStats("alice", null);

        assertThat(stats.getTotalEvents()).isZero();
        assertThat(stats.getPeakActivityCount()).isZero();
        assertThat(stats.getPeakActivityDate()).isNull();
        assertThat(stats.getAverageEventsPerDay()).isEqualTo(0.0);
    }
}
