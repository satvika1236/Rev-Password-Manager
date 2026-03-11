package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.TimelineEventDTO;
import com.revature.passwordmanager.model.analytics.TimelineEvent;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Pipeline orchestrator for the Feature 37 Vault Timeline.
 *
 * <p>Responsibilities:
 * <ol>
 *   <li>Build the title-to-entry cache from the database (one query per aggregate call).</li>
 *   <li>Delegate per-log enrichment to {@link TimelineEventEnricher} to produce typed
 *       {@link TimelineEvent} domain objects.</li>
 *   <li>Map domain objects to {@link TimelineEventDTO}s via {@link TimelineEventEnricher#toDtoList}.</li>
 * </ol>
 *
 * <p>This class intentionally owns <em>no enrichment logic itself</em> — category resolution,
 * severity classification, title extraction, and description building all live in
 * {@link TimelineEventEnricher}. This separation was specified in the Feature 37 proposal
 * and makes each concern independently testable.</p>
 */
@Component
@RequiredArgsConstructor
public class ActivityAggregator {

    private final VaultEntryRepository vaultEntryRepository;
    private final TimelineEventEnricher enricher;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Converts a list of raw audit log entries into enriched {@link TimelineEventDTO}s.
     *
     * @param logs   raw audit log entries for a user, ordered as desired (typically newest-first)
     * @param userId the owning user's id, used to build the title → entry cache
     * @return ordered list of DTOs preserving input order
     */
    public List<TimelineEventDTO> aggregate(List<AuditLog> logs, Long userId) {
        Map<String, VaultEntry> titleCache = buildTitleCache(userId);
        List<TimelineEvent> events = enricher.enrichAll(logs, titleCache);
        return enricher.toDtoList(events);
    }

    /**
     * Converts a single audit log entry to a {@link TimelineEventDTO}.
     * Exposed for use by callers that already hold a pre-built title cache.
     *
     * @param log        the audit log record
     * @param titleCache (lowercase title) → VaultEntry map
     * @return the enriched DTO
     */
    public TimelineEventDTO mapLogToEvent(AuditLog log, Map<String, VaultEntry> titleCache) {
        TimelineEvent event = enricher.enrich(log, titleCache);
        return enricher.toDto(event);
    }

    // ── Delegation helpers (retained for backward-compat with VaultTimelineService) ──

    /**
     * Extracts the vault entry title from an audit log details string.
     * Delegates to {@link TimelineEventEnricher#extractEntryTitle}.
     */
    public String extractEntryTitle(String details, AuditAction action) {
        return enricher.extractEntryTitle(details, action);
    }

    /**
     * Maps an AuditAction to its high-level category string.
     * Delegates to {@link TimelineEventEnricher#resolveActivityType} → category.
     */
    public String resolveCategory(AuditAction action) {
        var type = enricher.resolveActivityType(action);
        return type != null ? type.getCategory().name() : "SECURITY";
    }

    /**
     * Maps an AuditAction to its severity string.
     * Delegates to {@link TimelineEventEnricher#resolveSeverity}.
     */
    public String resolveSeverity(AuditAction action) {
        var type = enricher.resolveActivityType(action);
        return enricher.resolveSeverity(type);
    }

    // ── Title cache ───────────────────────────────────────────────────────────

    /**
     * Builds a map of (lowercase title) → {@link VaultEntry} for a user.
     * Includes soft-deleted entries so historical events can still be linked.
     * When multiple entries share the same title, the active (non-deleted) entry wins.
     *
     * @param userId the user's id
     * @return title cache map
     */
    public Map<String, VaultEntry> buildTitleCache(Long userId) {
        List<VaultEntry> all = vaultEntryRepository.findByUserId(userId);
        Map<String, VaultEntry> cache = new HashMap<>();
        for (VaultEntry e : all) {
            if (e.getTitle() == null) continue;
            String key = e.getTitle().toLowerCase();
            VaultEntry existing = cache.get(key);
            if (existing == null ||
                    (Boolean.TRUE.equals(existing.getIsDeleted()) && !Boolean.TRUE.equals(e.getIsDeleted()))) {
                cache.put(key, e);
            }
        }
        return cache;
    }
}
