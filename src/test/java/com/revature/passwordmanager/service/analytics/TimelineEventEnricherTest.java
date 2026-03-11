package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.TimelineEventDTO;
import com.revature.passwordmanager.model.analytics.ActivityType;
import com.revature.passwordmanager.model.analytics.TimelineCategory;
import com.revature.passwordmanager.model.analytics.TimelineEvent;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TimelineEventEnricher} — the enrichment logic extracted
 * from {@link ActivityAggregator} as part of the Feature 37 gap closure.
 */
class TimelineEventEnricherTest {

    // No Spring context needed — no dependencies
    private final TimelineEventEnricher enricher = new TimelineEventEnricher();

    private User user;
    private VaultEntry netflixEntry;

    @BeforeEach
    void setUp() {
        user = User.builder().id(1L).username("alice").build();
        netflixEntry = VaultEntry.builder()
                .id(10L).title("Netflix").websiteUrl("https://netflix.com")
                .user(user).isDeleted(false).build();
    }

    // ── resolveActivityType ───────────────────────────────────────────────────

    @Test
    void resolveActivityType_KnownActions_ShouldMapCorrectly() {
        assertThat(enricher.resolveActivityType(AuditAction.ENTRY_CREATED)).isEqualTo(ActivityType.ENTRY_CREATED);
        assertThat(enricher.resolveActivityType(AuditAction.LOGIN)).isEqualTo(ActivityType.LOGIN);
        assertThat(enricher.resolveActivityType(AuditAction.BREACH_DETECTED)).isEqualTo(ActivityType.BREACH_DETECTED);
        assertThat(enricher.resolveActivityType(AuditAction.SHARE_CREATED)).isEqualTo(ActivityType.SHARE_CREATED);
        assertThat(enricher.resolveActivityType(AuditAction.VAULT_EXPORTED)).isEqualTo(ActivityType.VAULT_EXPORTED);
        assertThat(enricher.resolveActivityType(AuditAction.TIMELINE_VIEWED)).isEqualTo(ActivityType.TIMELINE_VIEWED);
    }

    @Test
    void resolveActivityType_Null_ShouldReturnNull() {
        assertThat(enricher.resolveActivityType(null)).isNull();
    }

    // ── resolveSeverity ───────────────────────────────────────────────────────

    @Test
    void resolveSeverity_CriticalTypes() {
        assertThat(enricher.resolveSeverity(ActivityType.BREACH_DETECTED)).isEqualTo("CRITICAL");
        assertThat(enricher.resolveSeverity(ActivityType.LOGIN_FAILED)).isEqualTo("CRITICAL");
    }

    @Test
    void resolveSeverity_HighTypes() {
        assertThat(enricher.resolveSeverity(ActivityType.ENTRY_DELETED)).isEqualTo("HIGH");
        assertThat(enricher.resolveSeverity(ActivityType.SHARE_CREATED)).isEqualTo("HIGH");
        assertThat(enricher.resolveSeverity(ActivityType.BREACH_SCAN_RUN)).isEqualTo("HIGH");
    }

    @Test
    void resolveSeverity_MediumTypes() {
        assertThat(enricher.resolveSeverity(ActivityType.ENTRY_UPDATED)).isEqualTo("MEDIUM");
        assertThat(enricher.resolveSeverity(ActivityType.VAULT_EXPORTED)).isEqualTo("MEDIUM");
        assertThat(enricher.resolveSeverity(ActivityType.SHARE_REVOKED)).isEqualTo("MEDIUM");
        assertThat(enricher.resolveSeverity(ActivityType.BREACH_RESOLVED)).isEqualTo("MEDIUM");
    }

    @Test
    void resolveSeverity_LowTypes() {
        assertThat(enricher.resolveSeverity(ActivityType.ENTRY_CREATED)).isEqualTo("LOW");
        assertThat(enricher.resolveSeverity(ActivityType.LOGIN)).isEqualTo("LOW");
        assertThat(enricher.resolveSeverity(ActivityType.TIMELINE_VIEWED)).isEqualTo("LOW");
    }

    @Test
    void resolveSeverity_Null_ShouldReturnLow() {
        assertThat(enricher.resolveSeverity(null)).isEqualTo("LOW");
    }

    // ── ActivityType category mapping ─────────────────────────────────────────

    @Test
    void activityType_VaultActions_ShouldBelongToVaultCategory() {
        assertThat(ActivityType.ENTRY_CREATED.getCategory()).isEqualTo(TimelineCategory.VAULT);
        assertThat(ActivityType.ENTRY_UPDATED.getCategory()).isEqualTo(TimelineCategory.VAULT);
        assertThat(ActivityType.ENTRY_DELETED.getCategory()).isEqualTo(TimelineCategory.VAULT);
        assertThat(ActivityType.PASSWORD_VIEWED.getCategory()).isEqualTo(TimelineCategory.VAULT);
    }

    @Test
    void activityType_AuthActions_ShouldBelongToAuthCategory() {
        assertThat(ActivityType.LOGIN.getCategory()).isEqualTo(TimelineCategory.AUTH);
        assertThat(ActivityType.LOGIN_FAILED.getCategory()).isEqualTo(TimelineCategory.AUTH);
        assertThat(ActivityType.LOGOUT.getCategory()).isEqualTo(TimelineCategory.AUTH);
    }

    @Test
    void activityType_BreachActions_ShouldBelongToBreachCategory() {
        assertThat(ActivityType.BREACH_DETECTED.getCategory()).isEqualTo(TimelineCategory.BREACH);
        assertThat(ActivityType.BREACH_SCAN_RUN.getCategory()).isEqualTo(TimelineCategory.BREACH);
        assertThat(ActivityType.BREACH_RESOLVED.getCategory()).isEqualTo(TimelineCategory.BREACH);
    }

    @Test
    void activityType_SharingActions_ShouldBelongToSharingCategory() {
        assertThat(ActivityType.SHARE_CREATED.getCategory()).isEqualTo(TimelineCategory.SHARING);
        assertThat(ActivityType.SHARE_ACCESSED.getCategory()).isEqualTo(TimelineCategory.SHARING);
        assertThat(ActivityType.SHARE_REVOKED.getCategory()).isEqualTo(TimelineCategory.SHARING);
    }

    @Test
    void activityType_BackupActions_ShouldBelongToBackupCategory() {
        assertThat(ActivityType.VAULT_EXPORTED.getCategory()).isEqualTo(TimelineCategory.BACKUP);
    }

    @Test
    void activityType_SecurityActions_ShouldBelongToSecurityCategory() {
        assertThat(ActivityType.DASHBOARD_VIEWED.getCategory()).isEqualTo(TimelineCategory.SECURITY);
        assertThat(ActivityType.TIMELINE_VIEWED.getCategory()).isEqualTo(TimelineCategory.SECURITY);
    }

    // ── extractEntryTitle ─────────────────────────────────────────────────────

    @Test
    void extractEntryTitle_EntryCreated_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Created entry: Netflix", AuditAction.ENTRY_CREATED))
                .isEqualTo("Netflix");
    }

    @Test
    void extractEntryTitle_EntryUpdated_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Updated entry: Gmail", AuditAction.ENTRY_UPDATED))
                .isEqualTo("Gmail");
    }

    @Test
    void extractEntryTitle_EntryDeleted_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Deleted entry: Amazon", AuditAction.ENTRY_DELETED))
                .isEqualTo("Amazon");
    }

    @Test
    void extractEntryTitle_EntryRestored_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Restored entry: Spotify", AuditAction.ENTRY_RESTORED))
                .isEqualTo("Spotify");
    }

    @Test
    void extractEntryTitle_PasswordViewed_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Viewed password for entry: GitHub", AuditAction.PASSWORD_VIEWED))
                .isEqualTo("GitHub");
    }

    @Test
    void extractEntryTitle_ShareCreated_SingleQuotes_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Shared entry 'Netflix' token=abc123", AuditAction.SHARE_CREATED))
                .isEqualTo("Netflix");
    }

    @Test
    void extractEntryTitle_ShareRevoked_SingleQuotes_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Share revoked: id=5 entry='Bank Login'", AuditAction.SHARE_REVOKED))
                .isEqualTo("Bank Login");
    }

    @Test
    void extractEntryTitle_LoginAction_ShouldReturnNull() {
        assertThat(enricher.extractEntryTitle("Successful login", AuditAction.LOGIN)).isNull();
    }

    @Test
    void extractEntryTitle_NullDetails_ShouldReturnNull() {
        assertThat(enricher.extractEntryTitle(null, AuditAction.ENTRY_CREATED)).isNull();
    }

    @Test
    void extractEntryTitle_BlankDetails_ShouldReturnNull() {
        assertThat(enricher.extractEntryTitle("   ", AuditAction.ENTRY_CREATED)).isNull();
    }

    @Test
    void extractEntryTitle_UnknownPrefix_ShouldReturnNull() {
        assertThat(enricher.extractEntryTitle("Some random details", AuditAction.ENTRY_CREATED)).isNull();
    }

    @Test
    void extractEntryTitle_ToggledSensitive_ShouldExtractTitle() {
        assertThat(enricher.extractEntryTitle("Toggled sensitive flag for entry: SecretDoc", AuditAction.ENTRY_UPDATED))
                .isEqualTo("SecretDoc");
    }

    // ── enrich (single log) ───────────────────────────────────────────────────

    @Test
    void enrich_EntryCreatedLog_ShouldProduceDomainEvent() {
        Map<String, VaultEntry> cache = Map.of("netflix", netflixEntry);
        AuditLog log = AuditLog.builder().id(1L).user(user).action(AuditAction.ENTRY_CREATED)
                .details("Created entry: Netflix").timestamp(LocalDateTime.of(2026, 1, 15, 10, 30))
                .ipAddress("1.2.3.4").build();

        TimelineEvent event = enricher.enrich(log, cache);

        assertThat(event.getSourceLogId()).isEqualTo(1L);
        assertThat(event.getActivityType()).isEqualTo(ActivityType.ENTRY_CREATED);
        assertThat(event.getCategory()).isEqualTo(TimelineCategory.VAULT);
        assertThat(event.getVaultEntryTitle()).isEqualTo("Netflix");
        assertThat(event.getVaultEntryId()).isEqualTo(10L);
        assertThat(event.getWebsiteUrl()).isEqualTo("https://netflix.com");
        assertThat(event.getIpAddress()).isEqualTo("1.2.3.4");
        assertThat(event.getOccurredAt()).isEqualTo(LocalDateTime.of(2026, 1, 15, 10, 30));
    }

    @Test
    void enrich_LoginLog_ShouldHaveNullEntryFields() {
        Map<String, VaultEntry> cache = Collections.emptyMap();
        AuditLog log = AuditLog.builder().id(2L).user(user).action(AuditAction.LOGIN)
                .details("Successful login").ipAddress("10.0.0.1")
                .timestamp(LocalDateTime.now()).build();

        TimelineEvent event = enricher.enrich(log, cache);

        assertThat(event.getActivityType()).isEqualTo(ActivityType.LOGIN);
        assertThat(event.getCategory()).isEqualTo(TimelineCategory.AUTH);
        assertThat(event.getVaultEntryId()).isNull();
        assertThat(event.getVaultEntryTitle()).isNull();
    }

    // ── toDto ─────────────────────────────────────────────────────────────────

    @Test
    void toDto_ShouldMapAllFieldsCorrectly() {
        LocalDateTime ts = LocalDateTime.of(2026, 2, 1, 9, 0);
        TimelineEvent event = TimelineEvent.builder()
                .sourceLogId(5L).activityType(ActivityType.BREACH_DETECTED)
                .description("Breach found").vaultEntryId(10L).vaultEntryTitle("Netflix")
                .websiteUrl("https://netflix.com").ipAddress("5.6.7.8").occurredAt(ts).build();

        TimelineEventDTO dto = enricher.toDto(event);

        assertThat(dto.getId()).isEqualTo(5L);
        assertThat(dto.getEventType()).isEqualTo("BREACH_DETECTED");
        assertThat(dto.getCategory()).isEqualTo("BREACH");
        assertThat(dto.getSeverity()).isEqualTo("CRITICAL");
        assertThat(dto.getDescription()).isEqualTo("Breach found");
        assertThat(dto.getVaultEntryId()).isEqualTo(10L);
        assertThat(dto.getVaultEntryTitle()).isEqualTo("Netflix");
        assertThat(dto.getWebsiteUrl()).isEqualTo("https://netflix.com");
        assertThat(dto.getIpAddress()).isEqualTo("5.6.7.8");
        assertThat(dto.getTimestamp()).isEqualTo(ts);
    }

    @Test
    void toDto_NullActivityType_ShouldUseUnknownFallback() {
        TimelineEvent event = TimelineEvent.builder()
                .sourceLogId(1L).activityType(null).description("unknown")
                .occurredAt(LocalDateTime.now()).build();

        TimelineEventDTO dto = enricher.toDto(event);

        assertThat(dto.getEventType()).isEqualTo("UNKNOWN");
        assertThat(dto.getCategory()).isEqualTo("SECURITY");
        assertThat(dto.getSeverity()).isEqualTo("LOW");
    }

    // ── enrichAll + toDtoList ─────────────────────────────────────────────────

    @Test
    void enrichAll_ShouldProcessAllLogs() {
        Map<String, VaultEntry> cache = Map.of("netflix", netflixEntry);
        AuditLog l1 = AuditLog.builder().id(1L).user(user).action(AuditAction.ENTRY_CREATED)
                .details("Created entry: Netflix").timestamp(LocalDateTime.now()).build();
        AuditLog l2 = AuditLog.builder().id(2L).user(user).action(AuditAction.LOGIN)
                .details("Successful login").timestamp(LocalDateTime.now()).build();

        List<TimelineEvent> events = enricher.enrichAll(List.of(l1, l2), cache);

        assertThat(events).hasSize(2);
        assertThat(events.get(0).getActivityType()).isEqualTo(ActivityType.ENTRY_CREATED);
        assertThat(events.get(1).getActivityType()).isEqualTo(ActivityType.LOGIN);
    }

    @Test
    void toDtoList_ShouldMapAllEvents() {
        TimelineEvent e1 = TimelineEvent.builder().sourceLogId(1L)
                .activityType(ActivityType.LOGIN).description("login")
                .occurredAt(LocalDateTime.now()).build();
        TimelineEvent e2 = TimelineEvent.builder().sourceLogId(2L)
                .activityType(ActivityType.LOGOUT).description("logout")
                .occurredAt(LocalDateTime.now()).build();

        List<TimelineEventDTO> dtos = enricher.toDtoList(List.of(e1, e2));

        assertThat(dtos).hasSize(2);
        assertThat(dtos.get(0).getEventType()).isEqualTo("LOGIN");
        assertThat(dtos.get(1).getEventType()).isEqualTo("LOGOUT");
    }
}
