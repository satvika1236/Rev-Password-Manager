package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.response.*;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.analytics.VaultTimelineService;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = VaultTimelineController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class })
class VaultTimelineControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VaultTimelineService timelineService;
    @MockBean
    private JwtTokenProvider jwtTokenProvider;
    @MockBean
    private UserDetailsService userDetailsService;
    @MockBean
    private SessionService sessionService;
    @MockBean
    private RateLimitService rateLimitService;
    @MockBean
    private ClientIpUtil clientIpUtil;

    private VaultTimelineResponse sampleTimeline;
    private TimelineSummaryResponse sampleSummary;
    private EntryTimelineResponse sampleEntryTimeline;
    private TimelineStatsResponse sampleStats;

    @BeforeEach
    void setUp() {
        Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
        Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
                .thenReturn(true);
        Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString()))
                .thenReturn(100);

        TimelineEventDTO event = TimelineEventDTO.builder()
                .id(1L).eventType("ENTRY_CREATED").category("VAULT").severity("LOW")
                .description("Created entry: Netflix").vaultEntryTitle("Netflix").vaultEntryId(10L)
                .websiteUrl("https://netflix.com").timestamp(LocalDateTime.now().minusDays(3))
                .build();

        sampleTimeline = VaultTimelineResponse.builder()
                .events(List.of(event)).totalEvents(1).period("ALL_TIME")
                .startDate("2026-01-01").endDate("2026-02-27")
                .categoryBreakdown(VaultTimelineResponse.CategoryBreakdown.builder()
                        .vaultEvents(1).authEvents(0).sharingEvents(0)
                        .breachEvents(0).backupEvents(0).securityEvents(0).build())
                .build();

        sampleSummary = TimelineSummaryResponse.builder()
                .totalEntriesCreated(5).totalPasswordChanges(3).totalEntriesDeleted(1)
                .totalSharesCreated(2).totalBreachDetections(0).totalAuditEvents(20)
                .mostActiveDayOfWeek("Monday").mostActiveHour(10)
                .mostAccessedEntries(List.of())
                .weeklyActivity(List.of(
                        TimelineSummaryResponse.WeeklyActivityBucket.builder()
                                .weekStart("2026-02-17").eventCount(5).build()))
                .build();

        sampleEntryTimeline = EntryTimelineResponse.builder()
                .entryId(10L).entryTitle("Netflix").websiteUrl("https://netflix.com")
                .deleted(false).events(List.of(event))
                .passwordChangeCount(2).passwordViewCount(3).shareCount(1)
                .build();

        sampleStats = TimelineStatsResponse.builder()
                .eventsByType(Map.of("ENTRY_CREATED", 3, "LOGIN", 10))
                .eventsByCategory(Map.of("VAULT", 3, "AUTH", 10))
                .dailyActivity(List.of(
                        TimelineStatsResponse.DailyActivityBucket.builder()
                                .date("2026-02-27").count(5).vaultCount(3)
                                .securityCount(1).sharingCount(0).authCount(1).build()))
                .monthlyActivity(List.of(
                        TimelineStatsResponse.MonthlyActivityBucket.builder()
                                .month("2026-02").count(13).build()))
                .totalEvents(13).averageEventsPerDay(0.43)
                .peakActivityDate("2026-02-27").peakActivityCount(5)
                .build();
    }

    // ── GET /api/timeline ─────────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "alice")
    void getTimeline_NoParams_ShouldReturnFullTimeline() throws Exception {
        when(timelineService.getTimeline("alice", null, null)).thenReturn(sampleTimeline);

        mockMvc.perform(get("/api/timeline"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.totalEvents").value(1))
                .andExpect(jsonPath("$.period").value("ALL_TIME"))
                .andExpect(jsonPath("$.startDate").value("2026-01-01"))
                .andExpect(jsonPath("$.endDate").value("2026-02-27"))
                .andExpect(jsonPath("$.events[0].eventType").value("ENTRY_CREATED"))
                .andExpect(jsonPath("$.events[0].category").value("VAULT"))
                .andExpect(jsonPath("$.events[0].severity").value("LOW"))
                .andExpect(jsonPath("$.events[0].vaultEntryTitle").value("Netflix"))
                .andExpect(jsonPath("$.events[0].vaultEntryId").value(10))
                .andExpect(jsonPath("$.events[0].websiteUrl").value("https://netflix.com"))
                .andExpect(jsonPath("$.categoryBreakdown.vaultEvents").value(1))
                .andExpect(jsonPath("$.categoryBreakdown.authEvents").value(0));
    }

    @Test
    @WithMockUser(username = "alice")
    void getTimeline_WithDaysParam_ShouldPassThroughToService() throws Exception {
        VaultTimelineResponse filtered = VaultTimelineResponse.builder()
                .events(List.of()).totalEvents(0).period("LAST_30_DAYS")
                .startDate("2026-01-28").endDate("2026-02-27")
                .categoryBreakdown(VaultTimelineResponse.CategoryBreakdown.builder().build())
                .build();

        when(timelineService.getTimeline("alice", 30, null)).thenReturn(filtered);

        mockMvc.perform(get("/api/timeline").param("days", "30"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period").value("LAST_30_DAYS"))
                .andExpect(jsonPath("$.totalEvents").value(0));
    }

    @Test
    @WithMockUser(username = "alice")
    void getTimeline_WithCategoryFilter_ShouldPassThroughToService() throws Exception {
        when(timelineService.getTimeline("alice", null, "VAULT")).thenReturn(sampleTimeline);

        mockMvc.perform(get("/api/timeline").param("category", "VAULT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events[0].category").value("VAULT"));
    }

    @Test
    void getTimeline_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/timeline"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice")
    void getTimeline_EmptyVault_ShouldReturnEmptyEventsList() throws Exception {
        VaultTimelineResponse empty = VaultTimelineResponse.builder()
                .events(List.of()).totalEvents(0).period("ALL_TIME")
                .startDate("2026-02-27").endDate("2026-02-27")
                .categoryBreakdown(VaultTimelineResponse.CategoryBreakdown.builder().build())
                .build();

        when(timelineService.getTimeline("alice", null, null)).thenReturn(empty);

        mockMvc.perform(get("/api/timeline"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events").isArray())
                .andExpect(jsonPath("$.events").isEmpty())
                .andExpect(jsonPath("$.totalEvents").value(0));
    }

    // ── GET /api/timeline/summary ─────────────────────────────────────────────

    @Test
    @WithMockUser(username = "alice")
    void getSummary_ShouldReturnAllSummaryFields() throws Exception {
        when(timelineService.getSummary("alice")).thenReturn(sampleSummary);

        mockMvc.perform(get("/api/timeline/summary"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.totalEntriesCreated").value(5))
                .andExpect(jsonPath("$.totalPasswordChanges").value(3))
                .andExpect(jsonPath("$.totalEntriesDeleted").value(1))
                .andExpect(jsonPath("$.totalSharesCreated").value(2))
                .andExpect(jsonPath("$.totalBreachDetections").value(0))
                .andExpect(jsonPath("$.totalAuditEvents").value(20))
                .andExpect(jsonPath("$.mostActiveDayOfWeek").value("Monday"))
                .andExpect(jsonPath("$.mostActiveHour").value(10))
                .andExpect(jsonPath("$.weeklyActivity[0].weekStart").value("2026-02-17"))
                .andExpect(jsonPath("$.weeklyActivity[0].eventCount").value(5));
    }

    @Test
    void getSummary_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/timeline/summary"))
                .andExpect(status().isUnauthorized());
    }

    // ── GET /api/timeline/entry/{entryId} ─────────────────────────────────────

    @Test
    @WithMockUser(username = "alice")
    void getEntryTimeline_ValidId_ShouldReturnEntryTimeline() throws Exception {
        when(timelineService.getEntryTimeline("alice", 10L)).thenReturn(sampleEntryTimeline);

        mockMvc.perform(get("/api/timeline/entry/10"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.entryId").value(10))
                .andExpect(jsonPath("$.entryTitle").value("Netflix"))
                .andExpect(jsonPath("$.websiteUrl").value("https://netflix.com"))
                .andExpect(jsonPath("$.deleted").value(false))
                .andExpect(jsonPath("$.passwordChangeCount").value(2))
                .andExpect(jsonPath("$.passwordViewCount").value(3))
                .andExpect(jsonPath("$.shareCount").value(1))
                .andExpect(jsonPath("$.events[0].eventType").value("ENTRY_CREATED"));
    }

    @Test
    @WithMockUser(username = "alice")
    void getEntryTimeline_NotFound_ShouldReturn404() throws Exception {
        when(timelineService.getEntryTimeline("alice", 999L))
                .thenThrow(new ResourceNotFoundException("Vault entry not found: 999"));

        mockMvc.perform(get("/api/timeline/entry/999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void getEntryTimeline_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/timeline/entry/10"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice")
    void getEntryTimeline_DeletedEntry_ShouldReturnDeletedFlag() throws Exception {
        EntryTimelineResponse deletedResponse = EntryTimelineResponse.builder()
                .entryId(10L).entryTitle("Netflix").deleted(true).events(List.of())
                .passwordChangeCount(0).passwordViewCount(0).shareCount(0).build();

        when(timelineService.getEntryTimeline("alice", 10L)).thenReturn(deletedResponse);

        mockMvc.perform(get("/api/timeline/entry/10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deleted").value(true));
    }

    // ── GET /api/timeline/stats ───────────────────────────────────────────────

    @Test
    @WithMockUser(username = "alice")
    void getStats_ShouldReturnAllStatFields() throws Exception {
        when(timelineService.getStats("alice", null)).thenReturn(sampleStats);

        mockMvc.perform(get("/api/timeline/stats"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.totalEvents").value(13))
                .andExpect(jsonPath("$.averageEventsPerDay").value(0.43))
                .andExpect(jsonPath("$.peakActivityDate").value("2026-02-27"))
                .andExpect(jsonPath("$.peakActivityCount").value(5))
                .andExpect(jsonPath("$.eventsByType.ENTRY_CREATED").value(3))
                .andExpect(jsonPath("$.eventsByType.LOGIN").value(10))
                .andExpect(jsonPath("$.eventsByCategory.VAULT").value(3))
                .andExpect(jsonPath("$.eventsByCategory.AUTH").value(10))
                .andExpect(jsonPath("$.dailyActivity[0].date").value("2026-02-27"))
                .andExpect(jsonPath("$.dailyActivity[0].count").value(5))
                .andExpect(jsonPath("$.dailyActivity[0].vaultCount").value(3))
                .andExpect(jsonPath("$.dailyActivity[0].authCount").value(1))
                .andExpect(jsonPath("$.monthlyActivity[0].month").value("2026-02"))
                .andExpect(jsonPath("$.monthlyActivity[0].count").value(13));
    }

    @Test
    @WithMockUser(username = "alice")
    void getStats_WithDaysParam_ShouldPassThroughToService() throws Exception {
        when(timelineService.getStats("alice", 7)).thenReturn(sampleStats);

        mockMvc.perform(get("/api/timeline/stats").param("days", "7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(13));
    }

    @Test
    void getStats_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/timeline/stats"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice")
    void getStats_EmptyVault_ShouldReturnZeroStats() throws Exception {
        TimelineStatsResponse empty = TimelineStatsResponse.builder()
                .eventsByType(Map.of()).eventsByCategory(Map.of())
                .dailyActivity(List.of()).monthlyActivity(List.of())
                .totalEvents(0).averageEventsPerDay(0.0)
                .peakActivityDate(null).peakActivityCount(0)
                .build();

        when(timelineService.getStats("alice", null)).thenReturn(empty);

        mockMvc.perform(get("/api/timeline/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(0))
                .andExpect(jsonPath("$.dailyActivity").isArray())
                .andExpect(jsonPath("$.dailyActivity").isEmpty());
    }
}
