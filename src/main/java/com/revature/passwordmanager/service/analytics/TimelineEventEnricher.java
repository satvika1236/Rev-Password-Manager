package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.TimelineEventDTO;
import com.revature.passwordmanager.model.analytics.ActivityType;
import com.revature.passwordmanager.model.analytics.TimelineCategory;
import com.revature.passwordmanager.model.analytics.TimelineEvent;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.vault.VaultEntry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Enriches raw {@link AuditLog} records into fully-typed {@link TimelineEvent}
 * domain objects, and maps those domain objects to {@link TimelineEventDTO}s for
 * API responses.
 *
 * <p>This class was listed explicitly in the Feature 37 proposal as a required
 * component. Its responsibility is distinct from {@link ActivityAggregator}:</p>
 * <ul>
 *   <li>{@link ActivityAggregator} — pipeline orchestrator: builds the title cache,
 *       iterates logs, delegates to this enricher, returns DTOs.</li>
 *   <li>{@link TimelineEventEnricher} — enrichment logic: resolves {@link ActivityType},
 *       derives {@link TimelineCategory} and severity, builds descriptions, converts
 *       domain {@link TimelineEvent} → {@link TimelineEventDTO}.</li>
 * </ul>
 *
 * <p>Separating concerns this way makes enrichment logic independently testable
 * without needing a full {@code VaultEntryRepository} mock.</p>
 */
@Component
@RequiredArgsConstructor
public class TimelineEventEnricher {

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Enriches a single audit log into a typed {@link TimelineEvent}.
     *
     * @param log        the raw audit log record
     * @param titleCache pre-built (lowercase title → VaultEntry) map for title resolution
     * @return the enriched domain event
     */
    public TimelineEvent enrich(AuditLog log, Map<String, VaultEntry> titleCache) {
        AuditLog.AuditAction action = log.getAction();
        ActivityType activityType = resolveActivityType(action);

        String extractedTitle = extractEntryTitle(log.getDetails(), action);
        Long vaultEntryId = null;
        String vaultEntryTitle = null;
        String websiteUrl = null;

        if (extractedTitle != null) {
            vaultEntryTitle = extractedTitle;
            VaultEntry entry = titleCache.get(extractedTitle.toLowerCase());
            if (entry != null) {
                vaultEntryId = entry.getId();
                websiteUrl = entry.getWebsiteUrl();
            }
        }

        return TimelineEvent.builder()
                .sourceLogId(log.getId())
                .activityType(activityType)
                .description(buildDescription(log, action))
                .vaultEntryId(vaultEntryId)
                .vaultEntryTitle(vaultEntryTitle)
                .websiteUrl(websiteUrl)
                .ipAddress(log.getIpAddress())
                .occurredAt(log.getTimestamp())
                .build();
    }

    /**
     * Enriches a list of audit logs into typed {@link TimelineEvent} domain objects.
     *
     * @param logs       raw audit log records
     * @param titleCache pre-built (lowercase title → VaultEntry) map
     * @return ordered list preserving input order
     */
    public List<TimelineEvent> enrichAll(List<AuditLog> logs, Map<String, VaultEntry> titleCache) {
        return logs.stream()
                .map(log -> enrich(log, titleCache))
                .collect(Collectors.toList());
    }

    /**
     * Maps a {@link TimelineEvent} domain object to a {@link TimelineEventDTO}
     * for serialisation.
     *
     * @param event the enriched domain event
     * @return the DTO for API response
     */
    public TimelineEventDTO toDto(TimelineEvent event) {
        return TimelineEventDTO.builder()
                .id(event.getSourceLogId())
                .eventType(event.getActivityType() != null
                        ? event.getActivityType().name() : "UNKNOWN")
                .category(event.getCategory() != null
                        ? event.getCategory().name() : "SECURITY")
                .description(event.getDescription())
                .vaultEntryId(event.getVaultEntryId())
                .vaultEntryTitle(event.getVaultEntryTitle())
                .websiteUrl(event.getWebsiteUrl())
                .ipAddress(event.getIpAddress())
                .timestamp(event.getOccurredAt())
                .severity(resolveSeverity(event.getActivityType()))
                .build();
    }

    /**
     * Maps a list of {@link TimelineEvent} domain objects to DTOs.
     *
     * @param events enriched domain events
     * @return list of DTOs
     */
    public List<TimelineEventDTO> toDtoList(List<TimelineEvent> events) {
        return events.stream().map(this::toDto).collect(Collectors.toList());
    }

    // ── ActivityType resolution ───────────────────────────────────────────────

    /**
     * Resolves the strongly-typed {@link ActivityType} from an {@link AuditLog.AuditAction}.
     * Falls back to {@code null} for any action not mapped in {@link ActivityType}.
     */
    public ActivityType resolveActivityType(AuditLog.AuditAction action) {
        if (action == null) return null;
        return ActivityType.fromAuditAction(action.name());
    }

    // ── Severity resolution ───────────────────────────────────────────────────

    /**
     * Maps an {@link ActivityType} to a severity level string for frontend highlighting.
     *
     * @param type the activity type (may be null)
     * @return one of: {@code "CRITICAL"}, {@code "HIGH"}, {@code "MEDIUM"}, {@code "LOW"}
     */
    public String resolveSeverity(ActivityType type) {
        if (type == null) return "LOW";
        return switch (type) {
            case BREACH_DETECTED, LOGIN_FAILED -> "CRITICAL";
            case ENTRY_DELETED, SHARE_CREATED, BREACH_SCAN_RUN -> "HIGH";
            case ENTRY_UPDATED, ENTRY_RESTORED, SHARE_ACCESSED, SHARE_REVOKED,
                 VAULT_EXPORTED, BREACH_RESOLVED -> "MEDIUM";
            default -> "LOW";
        };
    }

    // ── Entry title extraction ────────────────────────────────────────────────

    /**
     * Extracts the vault entry title from an audit log details string using the
     * format conventions established by VaultService and SecureShareService.
     *
     * <p>Supported formats:
     * <ul>
     *   <li>{@code "Created entry: <title>"}</li>
     *   <li>{@code "Updated entry: <title>"}</li>
     *   <li>{@code "Deleted entry: <title>"}</li>
     *   <li>{@code "Restored entry: <title>"}</li>
     *   <li>{@code "Viewed password for entry: <title>"}</li>
     *   <li>{@code "Toggled sensitive flag for entry: <title>"}</li>
     *   <li>{@code "Shared entry '<title>' token=..."}</li>
     *   <li>{@code "Share revoked: id=N entry='<title>'"}</li>
     * </ul>
     *
     * @param details audit log details string
     * @param action  audit action used to select the right parser
     * @return extracted title, or {@code null} if not parseable
     */
    public String extractEntryTitle(String details, AuditLog.AuditAction action) {
        if (details == null || details.isBlank()) return null;
        return switch (action) {
            case ENTRY_CREATED -> extractAfterPrefix(details, "Created entry: ");
            case ENTRY_UPDATED -> {
                String t = extractAfterPrefix(details, "Updated entry: ");
                if (t == null) t = extractAfterPrefix(details, "Toggled sensitive flag for entry: ");
                yield t;
            }
            case ENTRY_DELETED -> extractAfterPrefix(details, "Deleted entry: ");
            case ENTRY_RESTORED -> extractAfterPrefix(details, "Restored entry: ");
            case PASSWORD_VIEWED -> extractAfterPrefix(details, "Viewed password for entry: ");
            case SHARE_CREATED -> extractQuotedTitle(details, "Shared entry '");
            case SHARE_REVOKED -> extractQuotedTitle(details, "entry='");
            default -> null;
        };
    }

    // ── Description builder ───────────────────────────────────────────────────

    private String buildDescription(AuditLog log, AuditLog.AuditAction action) {
        String details = log.getDetails();
        return switch (action) {
            case LOGIN -> "Successful login"
                    + (log.getIpAddress() != null ? " from " + log.getIpAddress() : "");
            case LOGIN_FAILED -> "Failed login attempt"
                    + (log.getIpAddress() != null ? " from " + log.getIpAddress() : "");
            case LOGOUT -> "Session ended";
            case BREACH_SCAN_RUN -> "Breach scan executed against HaveIBeenPwned";
            case DASHBOARD_VIEWED -> "Security dashboard accessed";
            case TIMELINE_VIEWED -> "Vault timeline accessed";
            default -> details != null
                    ? details : action.name().replace('_', ' ').toLowerCase();
        };
    }

    // ── String helpers ────────────────────────────────────────────────────────

    private String extractAfterPrefix(String details, String prefix) {
        if (!details.startsWith(prefix)) return null;
        String rest = details.substring(prefix.length()).trim();
        for (String stop : new String[]{"' token=", " token=", " (", "\n"}) {
            int idx = rest.indexOf(stop);
            if (idx > 0) rest = rest.substring(0, idx);
        }
        return rest.isBlank() ? null : rest.trim();
    }

    private String extractQuotedTitle(String details, String prefix) {
        int start = details.indexOf(prefix);
        if (start < 0) return null;
        int titleStart = start + prefix.length();
        int titleEnd = details.indexOf("'", titleStart);
        if (titleEnd < 0) return null;
        String title = details.substring(titleStart, titleEnd).trim();
        return title.isBlank() ? null : title;
    }
}
