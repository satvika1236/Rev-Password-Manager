package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.TimelineEventDTO;
import com.revature.passwordmanager.model.analytics.TimelineEvent;
import com.revature.passwordmanager.model.analytics.ActivityType;
import com.revature.passwordmanager.model.analytics.TimelineCategory;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ActivityAggregator} — the pipeline orchestrator.
 *
 * <p>Since enrichment logic now lives in {@link TimelineEventEnricher}, these tests
 * focus on the orchestration responsibilities: building the title cache, wiring
 * enricher calls, and mapping results to DTOs. Category/severity/title-extraction
 * logic is tested in {@link TimelineEventEnricherTest}.</p>
 */
@ExtendWith(MockitoExtension.class)
class ActivityAggregatorTest {

    @Mock
    private VaultEntryRepository vaultEntryRepository;

    @Mock
    private TimelineEventEnricher enricher;

    @InjectMocks
    private ActivityAggregator aggregator;

    private User user;
    private VaultEntry netflixEntry;
    private VaultEntry gmailEntry;

    @BeforeEach
    void setUp() {
        user = User.builder().id(1L).username("alice").build();

        netflixEntry = VaultEntry.builder()
                .id(10L).title("Netflix").websiteUrl("https://netflix.com")
                .user(user).isDeleted(false).build();

        gmailEntry = VaultEntry.builder()
                .id(20L).title("Gmail").websiteUrl("https://gmail.com")
                .user(user).isDeleted(false).build();
    }

    // ── buildTitleCache ───────────────────────────────────────────────────────

    @Test
    void buildTitleCache_ShouldIndexByLowercaseTitle() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(netflixEntry, gmailEntry));

        Map<String, VaultEntry> cache = aggregator.buildTitleCache(1L);

        assertThat(cache).containsKey("netflix");
        assertThat(cache).containsKey("gmail");
        assertThat(cache.get("netflix").getId()).isEqualTo(10L);
        assertThat(cache.get("gmail").getId()).isEqualTo(20L);
    }

    @Test
    void buildTitleCache_EmptyVault_ShouldReturnEmptyMap() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(Collections.emptyList());

        Map<String, VaultEntry> cache = aggregator.buildTitleCache(1L);

        assertThat(cache).isEmpty();
    }

    @Test
    void buildTitleCache_TitleConflict_ActiveEntryWins() {
        VaultEntry deletedNetflix = VaultEntry.builder()
                .id(99L).title("Netflix").websiteUrl("https://old-netflix.com")
                .user(user).isDeleted(true).build();

        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(deletedNetflix, netflixEntry));

        Map<String, VaultEntry> cache = aggregator.buildTitleCache(1L);

        assertThat(cache.get("netflix").getId()).isEqualTo(10L);
    }

    @Test
    void buildTitleCache_NullTitleEntry_ShouldBeSkipped() {
        VaultEntry nullTitle = VaultEntry.builder().id(99L).title(null).user(user).isDeleted(false).build();
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(nullTitle, netflixEntry));

        Map<String, VaultEntry> cache = aggregator.buildTitleCache(1L);

        assertThat(cache).containsKey("netflix");
        assertThat(cache).doesNotContainKey(null);
    }

    // ── aggregate (orchestration) ─────────────────────────────────────────────

    @Test
    void aggregate_ShouldCallEnricherAndReturnDTOs() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(netflixEntry));

        AuditLog log = AuditLog.builder().id(1L).user(user).action(AuditAction.ENTRY_CREATED)
                .details("Created entry: Netflix").timestamp(LocalDateTime.now()).build();

        TimelineEvent domainEvent = TimelineEvent.builder()
                .sourceLogId(1L).activityType(ActivityType.ENTRY_CREATED)
                .description("Created entry: Netflix").vaultEntryId(10L)
                .vaultEntryTitle("Netflix").websiteUrl("https://netflix.com")
                .occurredAt(log.getTimestamp()).build();

        TimelineEventDTO dto = TimelineEventDTO.builder()
                .id(1L).eventType("ENTRY_CREATED").category("VAULT").severity("LOW")
                .description("Created entry: Netflix").vaultEntryId(10L)
                .vaultEntryTitle("Netflix").websiteUrl("https://netflix.com")
                .timestamp(log.getTimestamp()).build();

        when(enricher.enrichAll(anyList(), anyMap())).thenReturn(List.of(domainEvent));
        when(enricher.toDtoList(anyList())).thenReturn(List.of(dto));

        List<TimelineEventDTO> result = aggregator.aggregate(List.of(log), 1L);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEventType()).isEqualTo("ENTRY_CREATED");
        assertThat(result.get(0).getVaultEntryTitle()).isEqualTo("Netflix");
    }

    @Test
    void aggregate_EmptyLogs_ShouldReturnEmptyList() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(Collections.emptyList());
        when(enricher.enrichAll(anyList(), anyMap())).thenReturn(Collections.emptyList());
        when(enricher.toDtoList(anyList())).thenReturn(Collections.emptyList());

        List<TimelineEventDTO> result = aggregator.aggregate(Collections.emptyList(), 1L);

        assertThat(result).isEmpty();
    }

    @Test
    void aggregate_PreservesResultOrderFromEnricher() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(Collections.emptyList());

        LocalDateTime t1 = LocalDateTime.of(2026, 1, 1, 10, 0);
        LocalDateTime t2 = LocalDateTime.of(2026, 1, 2, 10, 0);

        TimelineEventDTO dto1 = TimelineEventDTO.builder().id(1L).timestamp(t1)
                .eventType("LOGIN").category("AUTH").severity("LOW").build();
        TimelineEventDTO dto2 = TimelineEventDTO.builder().id(2L).timestamp(t2)
                .eventType("LOGOUT").category("AUTH").severity("LOW").build();

        when(enricher.enrichAll(anyList(), anyMap())).thenReturn(Collections.emptyList());
        when(enricher.toDtoList(anyList())).thenReturn(List.of(dto1, dto2));

        AuditLog l1 = AuditLog.builder().id(1L).user(user).action(AuditAction.LOGIN)
                .details("login").timestamp(t1).build();
        AuditLog l2 = AuditLog.builder().id(2L).user(user).action(AuditAction.LOGOUT)
                .details("logout").timestamp(t2).build();

        List<TimelineEventDTO> result = aggregator.aggregate(List.of(l1, l2), 1L);

        assertThat(result.get(0).getTimestamp()).isEqualTo(t1);
        assertThat(result.get(1).getTimestamp()).isEqualTo(t2);
    }

    // ── delegation methods ────────────────────────────────────────────────────

    @Test
    void extractEntryTitle_DelegatesToEnricher() {
        when(enricher.extractEntryTitle("Created entry: Netflix", AuditAction.ENTRY_CREATED))
                .thenReturn("Netflix");

        String result = aggregator.extractEntryTitle("Created entry: Netflix", AuditAction.ENTRY_CREATED);

        assertThat(result).isEqualTo("Netflix");
    }

    @Test
    void resolveCategory_DelegatesToEnricher() {
        when(enricher.resolveActivityType(AuditAction.ENTRY_CREATED))
                .thenReturn(ActivityType.ENTRY_CREATED);

        String result = aggregator.resolveCategory(AuditAction.ENTRY_CREATED);

        assertThat(result).isEqualTo("VAULT");
    }

    @Test
    void resolveCategory_NullActivityType_ReturnsSecurityDefault() {
        when(enricher.resolveActivityType(AuditAction.LOGIN)).thenReturn(null);

        String result = aggregator.resolveCategory(AuditAction.LOGIN);

        assertThat(result).isEqualTo("SECURITY");
    }
}
