package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.response.EntryTimelineResponse;
import com.revature.passwordmanager.dto.response.TimelineStatsResponse;
import com.revature.passwordmanager.dto.response.TimelineSummaryResponse;
import com.revature.passwordmanager.dto.response.VaultTimelineResponse;
import com.revature.passwordmanager.service.analytics.VaultTimelineService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for Feature 37: Vault Timeline Visualization.
 * <p>
 * Exposes read-only endpoints for visualising the full history of vault activity.
 * All endpoints require authentication — the timeline is user-scoped and never
 * exposes another user's data.
 * </p>
 *
 * Base URL: {@code /api/timeline}
 */
@RestController
@RequestMapping("/api/timeline")
@RequiredArgsConstructor
@Tag(name = "Vault Timeline", description = "Feature 37 – Vault Timeline Visualization: chronological activity feed and analytics")
public class VaultTimelineController {

    private final VaultTimelineService timelineService;

    /**
     * Returns the full vault activity timeline for the authenticated user.
     *
     * <p>Example response event types:</p>
     * <ul>
     *   <li>ENTRY_CREATED, ENTRY_UPDATED, ENTRY_DELETED, ENTRY_RESTORED</li>
     *   <li>PASSWORD_VIEWED, SHARE_CREATED, SHARE_ACCESSED, SHARE_REVOKED</li>
     *   <li>BREACH_DETECTED, BREACH_RESOLVED, VAULT_EXPORTED</li>
     *   <li>LOGIN, LOGOUT, LOGIN_FAILED</li>
     * </ul>
     *
     * @param days           optional: number of days back to fetch (omit for all-time)
     * @param categoryFilter optional: filter by category — VAULT, AUTH, BREACH, SHARING, BACKUP, SECURITY
     * @return {@link VaultTimelineResponse} with events list and category breakdown
     */
    @Operation(
        summary = "Get full vault timeline",
        description = "Returns the complete chronological activity timeline for the authenticated user. " +
                      "Optionally filter by time range (?days=N) and/or event category (?category=VAULT)."
    )
    @GetMapping
    public ResponseEntity<VaultTimelineResponse> getTimeline(
            @Parameter(description = "Number of past days to include (omit for all-time)")
            @RequestParam(required = false) Integer days,
            @Parameter(description = "Filter by category: VAULT, AUTH, BREACH, SHARING, BACKUP, SECURITY")
            @RequestParam(name = "category", required = false) String categoryFilter) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(timelineService.getTimeline(username, days, categoryFilter));
    }

    /**
     * Returns a high-level summary of vault activity statistics.
     *
     * <p>Includes: total entries created/deleted, password changes, shares created,
     * breach detections, most active day/hour, top-5 most accessed entries,
     * and a 12-week activity histogram.</p>
     *
     * @return {@link TimelineSummaryResponse} with aggregated statistics
     */
    @Operation(
        summary = "Get timeline activity summary",
        description = "Returns high-level summary statistics: total events by type, most active day/hour, " +
                      "top accessed entries, and a 12-week weekly activity histogram."
    )
    @GetMapping("/summary")
    public ResponseEntity<TimelineSummaryResponse> getSummary() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(timelineService.getSummary(username));
    }

    /**
     * Returns the timeline scoped to a single vault entry — showing its full lifecycle.
     *
     * <p>Includes creation, all updates, password views, sharing events, and deletion.
     * Returns HTTP 404 if the entry does not exist or does not belong to the current user.</p>
     *
     * @param entryId the vault entry id
     * @return {@link EntryTimelineResponse} with per-entry events and counts
     */
    @Operation(
        summary = "Get timeline for a specific vault entry",
        description = "Returns the full lifecycle timeline for a single vault entry: creation, updates, " +
                      "password views, share events, and deletion. Entry must belong to the current user."
    )
    @GetMapping("/entry/{entryId}")
    public ResponseEntity<EntryTimelineResponse> getEntryTimeline(
            @Parameter(description = "Vault entry id")
            @PathVariable Long entryId) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(timelineService.getEntryTimeline(username, entryId));
    }

    /**
     * Returns aggregated activity statistics optimised for chart rendering.
     *
     * <p>Provides daily and monthly activity buckets (with category breakdown per day),
     * event counts by type and category, peak activity date, and averages.</p>
     *
     * @param days optional: number of days to include in the stats window (omit for all-time)
     * @return {@link TimelineStatsResponse} with chart-ready data
     */
    @Operation(
        summary = "Get timeline activity statistics",
        description = "Returns chart-ready aggregated statistics: daily activity with category breakdown, " +
                      "monthly totals, event counts by type, peak activity date, and average events per day."
    )
    @GetMapping("/stats")
    public ResponseEntity<TimelineStatsResponse> getStats(
            @Parameter(description = "Number of past days to include in stats (omit for all-time)")
            @RequestParam(required = false) Integer days) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(timelineService.getStats(username, days));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private String getCurrentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
