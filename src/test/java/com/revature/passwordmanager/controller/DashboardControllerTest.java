package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.response.PasswordAgeResponse;
import com.revature.passwordmanager.dto.response.PasswordHealthMetricsResponse;
import com.revature.passwordmanager.dto.response.ReusedPasswordResponse;
import com.revature.passwordmanager.dto.response.SecurityScoreResponse;
import com.revature.passwordmanager.dto.response.SecurityTrendResponse;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.dashboard.PasswordStrengthDashboardService;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = DashboardController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class })
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PasswordStrengthDashboardService dashboardService;

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

    @BeforeEach
    void setUp() {
        Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
        Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.anyString(),
                ArgumentMatchers.anyString())).thenReturn(true);
        Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
                ArgumentMatchers.anyString())).thenReturn(100);
    }

    // ── GET /api/dashboard/security-score ────────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityScore_ShouldReturnScore() throws Exception {
        SecurityScoreResponse response = SecurityScoreResponse.builder()
                .overallScore(82)
                .scoreLabel("Good")
                .totalPasswords(10)
                .strongPasswords(7)
                .fairPasswords(2)
                .weakPasswords(1)
                .reusedPasswords(0)
                .oldPasswords(1)
                .recommendation("Update 1 old password to improve your score.")
                .build();

        when(dashboardService.getSecurityScore("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/security-score"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.overallScore").value(82))
                .andExpect(jsonPath("$.scoreLabel").value("Good"))
                .andExpect(jsonPath("$.totalPasswords").value(10))
                .andExpect(jsonPath("$.strongPasswords").value(7))
                .andExpect(jsonPath("$.fairPasswords").value(2))
                .andExpect(jsonPath("$.weakPasswords").value(1))
                .andExpect(jsonPath("$.reusedPasswords").value(0))
                .andExpect(jsonPath("$.oldPasswords").value(1))
                .andExpect(jsonPath("$.recommendation").isNotEmpty());
    }

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityScore_EmptyVault_ShouldReturn100() throws Exception {
        SecurityScoreResponse response = SecurityScoreResponse.builder()
                .overallScore(100)
                .scoreLabel("Excellent")
                .totalPasswords(0)
                .recommendation("Add passwords to your vault to start tracking security metrics.")
                .build();

        when(dashboardService.getSecurityScore("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/security-score"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.overallScore").value(100))
                .andExpect(jsonPath("$.scoreLabel").value("Excellent"))
                .andExpect(jsonPath("$.totalPasswords").value(0));
    }

    @Test
    void getSecurityScore_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/dashboard/security-score"))
                .andExpect(status().isUnauthorized());
    }

    // ── GET /api/dashboard/password-health ───────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getPasswordHealth_ShouldReturnBreakdown() throws Exception {
        PasswordHealthMetricsResponse.PasswordCategoryBreakdown breakdown = PasswordHealthMetricsResponse.PasswordCategoryBreakdown
                .builder()
                .categoryName("Social Media")
                .count(3)
                .averageScore(72.5)
                .weakCount(0)
                .build();

        PasswordHealthMetricsResponse response = PasswordHealthMetricsResponse.builder()
                .totalPasswords(10)
                .strongCount(4)
                .goodCount(3)
                .fairCount(2)
                .weakCount(1)
                .veryWeakCount(0)
                .averageStrengthScore(68.5)
                .categoryBreakdowns(List.of(breakdown))
                .build();

        when(dashboardService.getPasswordHealth("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/password-health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalPasswords").value(10))
                .andExpect(jsonPath("$.strongCount").value(4))
                .andExpect(jsonPath("$.goodCount").value(3))
                .andExpect(jsonPath("$.fairCount").value(2))
                .andExpect(jsonPath("$.weakCount").value(1))
                .andExpect(jsonPath("$.veryWeakCount").value(0))
                .andExpect(jsonPath("$.averageStrengthScore").value(68.5))
                .andExpect(jsonPath("$.categoryBreakdowns[0].categoryName").value("Social Media"))
                .andExpect(jsonPath("$.categoryBreakdowns[0].count").value(3));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getPasswordHealth_EmptyVault_ShouldReturnZeros() throws Exception {
        PasswordHealthMetricsResponse response = PasswordHealthMetricsResponse.builder()
                .totalPasswords(0)
                .strongCount(0)
                .goodCount(0)
                .fairCount(0)
                .weakCount(0)
                .veryWeakCount(0)
                .averageStrengthScore(0.0)
                .categoryBreakdowns(List.of())
                .build();

        when(dashboardService.getPasswordHealth("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/password-health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalPasswords").value(0))
                .andExpect(jsonPath("$.averageStrengthScore").value(0.0))
                .andExpect(jsonPath("$.categoryBreakdowns").isArray())
                .andExpect(jsonPath("$.categoryBreakdowns").isEmpty());
    }

    @Test
    void getPasswordHealth_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/dashboard/password-health"))
                .andExpect(status().isUnauthorized());
    }

    // ── GET /api/dashboard/reused-passwords ──────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getReusedPasswords_ShouldReturnGroups() throws Exception {
        ReusedPasswordResponse.ReusedEntryInfo entry1 = ReusedPasswordResponse.ReusedEntryInfo.builder()
                .entryId(1L).title("Gmail").username("user@gmail.com").websiteUrl("https://gmail.com")
                .build();
        ReusedPasswordResponse.ReusedEntryInfo entry2 = ReusedPasswordResponse.ReusedEntryInfo.builder()
                .entryId(2L).title("Yahoo").username("user@yahoo.com").websiteUrl("https://yahoo.com")
                .build();

        ReusedPasswordResponse.ReusedPasswordGroup group = ReusedPasswordResponse.ReusedPasswordGroup.builder()
                .reuseCount(2)
                .entries(List.of(entry1, entry2))
                .build();

        ReusedPasswordResponse response = ReusedPasswordResponse.builder()
                .totalReusedGroups(1)
                .totalAffectedEntries(2)
                .reusedGroups(List.of(group))
                .build();

        when(dashboardService.getReusedPasswords("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/reused-passwords"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalReusedGroups").value(1))
                .andExpect(jsonPath("$.totalAffectedEntries").value(2))
                .andExpect(jsonPath("$.reusedGroups[0].reuseCount").value(2))
                .andExpect(jsonPath("$.reusedGroups[0].entries[0].title").value("Gmail"))
                .andExpect(jsonPath("$.reusedGroups[0].entries[1].title").value("Yahoo"));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getReusedPasswords_NoReuse_ShouldReturnEmpty() throws Exception {
        ReusedPasswordResponse response = ReusedPasswordResponse.builder()
                .totalReusedGroups(0)
                .totalAffectedEntries(0)
                .reusedGroups(List.of())
                .build();

        when(dashboardService.getReusedPasswords("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/reused-passwords"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalReusedGroups").value(0))
                .andExpect(jsonPath("$.totalAffectedEntries").value(0))
                .andExpect(jsonPath("$.reusedGroups").isEmpty());
    }

    @Test
    void getReusedPasswords_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/dashboard/reused-passwords"))
                .andExpect(status().isUnauthorized());
    }

    // ── GET /api/dashboard/password-age ──────────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getPasswordAge_ShouldReturnDistribution() throws Exception {
        List<PasswordAgeResponse.AgeDistributionBucket> distribution = List.of(
                PasswordAgeResponse.AgeDistributionBucket.builder()
                        .label("< 30 days").count(5).minDays(0).maxDays(29).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder()
                        .label("30-90 days").count(3).minDays(30).maxDays(90).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder()
                        .label("90-180 days").count(1).minDays(91).maxDays(180).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder()
                        .label("> 180 days").count(1).minDays(181).maxDays(Integer.MAX_VALUE)
                        .build());

        PasswordAgeResponse response = PasswordAgeResponse.builder()
                .totalPasswords(10)
                .freshCount(5)
                .agingCount(3)
                .oldCount(1)
                .ancientCount(1)
                .averageAgeInDays(45.3)
                .distribution(distribution)
                .build();

        when(dashboardService.getPasswordAge("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/password-age"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalPasswords").value(10))
                .andExpect(jsonPath("$.freshCount").value(5))
                .andExpect(jsonPath("$.agingCount").value(3))
                .andExpect(jsonPath("$.oldCount").value(1))
                .andExpect(jsonPath("$.ancientCount").value(1))
                .andExpect(jsonPath("$.averageAgeInDays").value(45.3))
                .andExpect(jsonPath("$.distribution[0].label").value("< 30 days"))
                .andExpect(jsonPath("$.distribution[0].count").value(5));
    }

    @Test
    void getPasswordAge_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/dashboard/password-age"))
                .andExpect(status().isUnauthorized());
    }

    // ── GET /api/dashboard/trends ─────────────────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityTrends_DefaultDays_ShouldReturnTrend() throws Exception {
        SecurityTrendResponse.TrendDataPoint point = SecurityTrendResponse.TrendDataPoint.builder()
                .recordedAt(LocalDateTime.now().minusDays(5))
                .overallScore(75)
                .weakPasswordsCount(2)
                .reusedPasswordsCount(1)
                .oldPasswordsCount(1)
                .build();

        SecurityTrendResponse response = SecurityTrendResponse.builder()
                .trendPoints(List.of(point))
                .scoreChange(5)
                .trendDirection("IMPROVING")
                .periodLabel("30-day trend")
                .build();

        when(dashboardService.getSecurityTrends(eq("testuser"), eq(30))).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/trends"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scoreChange").value(5))
                .andExpect(jsonPath("$.trendDirection").value("IMPROVING"))
                .andExpect(jsonPath("$.periodLabel").value("30-day trend"))
                .andExpect(jsonPath("$.trendPoints[0].overallScore").value(75));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityTrends_CustomDays_ShouldPassDaysParam() throws Exception {
        SecurityTrendResponse response = SecurityTrendResponse.builder()
                .trendPoints(List.of())
                .scoreChange(0)
                .trendDirection("STABLE")
                .periodLabel("7-day trend")
                .build();

        when(dashboardService.getSecurityTrends(eq("testuser"), eq(7))).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/trends").param("days", "7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trendDirection").value("STABLE"))
                .andExpect(jsonPath("$.periodLabel").value("7-day trend"));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityTrends_DecliningScore_ShouldReturnDeclining() throws Exception {
        SecurityTrendResponse response = SecurityTrendResponse.builder()
                .trendPoints(List.of())
                .scoreChange(-10)
                .trendDirection("DECLINING")
                .periodLabel("30-day trend")
                .build();

        when(dashboardService.getSecurityTrends(eq("testuser"), anyInt())).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/trends"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scoreChange").value(-10))
                .andExpect(jsonPath("$.trendDirection").value("DECLINING"));
    }

    @Test
    void getSecurityTrends_Unauthenticated_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/dashboard/trends"))
                .andExpect(status().isUnauthorized());
    }

    // ── Response Content-Type ─────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void allEndpoints_ShouldReturnJsonContentType() throws Exception {
        when(dashboardService.getSecurityScore("testuser"))
                .thenReturn(SecurityScoreResponse.builder().overallScore(80).scoreLabel("Good")
                        .build());
        when(dashboardService.getPasswordHealth("testuser"))
                .thenReturn(PasswordHealthMetricsResponse.builder().totalPasswords(0)
                        .categoryBreakdowns(List.of()).build());
        when(dashboardService.getReusedPasswords("testuser"))
                .thenReturn(ReusedPasswordResponse.builder().totalReusedGroups(0)
                        .totalAffectedEntries(0).reusedGroups(List.of()).build());
        when(dashboardService.getPasswordAge("testuser"))
                .thenReturn(PasswordAgeResponse.builder().totalPasswords(0).distribution(List.of())
                        .build());
        when(dashboardService.getSecurityTrends(eq("testuser"), eq(30)))
                .thenReturn(SecurityTrendResponse.builder().trendPoints(List.of()).scoreChange(0)
                        .trendDirection("STABLE").periodLabel("30-day trend").build());

        mockMvc.perform(get("/api/dashboard/security-score"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
        mockMvc.perform(get("/api/dashboard/password-health"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
        mockMvc.perform(get("/api/dashboard/reused-passwords"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
        mockMvc.perform(get("/api/dashboard/password-age"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
        mockMvc.perform(get("/api/dashboard/trends"))
                .andExpect(content().contentTypeCompatibleWith("application/json"));
    }

    // ── Full field assertions on nested objects ───────────────────────────────

    @Test
    @WithMockUser(username = "testuser")
    void getPasswordHealth_CategoryBreakdown_ShouldAssertAllFields() throws Exception {
        PasswordHealthMetricsResponse.PasswordCategoryBreakdown breakdown = PasswordHealthMetricsResponse.PasswordCategoryBreakdown
                .builder()
                .categoryName("Work")
                .count(5)
                .averageScore(61.2)
                .weakCount(2)
                .build();

        PasswordHealthMetricsResponse response = PasswordHealthMetricsResponse.builder()
                .totalPasswords(5)
                .strongCount(1).goodCount(1).fairCount(1).weakCount(1).veryWeakCount(1)
                .averageStrengthScore(61.2)
                .categoryBreakdowns(List.of(breakdown))
                .build();

        when(dashboardService.getPasswordHealth("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/password-health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.categoryBreakdowns[0].categoryName").value("Work"))
                .andExpect(jsonPath("$.categoryBreakdowns[0].count").value(5))
                .andExpect(jsonPath("$.categoryBreakdowns[0].averageScore").value(61.2))
                .andExpect(jsonPath("$.categoryBreakdowns[0].weakCount").value(2));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getReusedPasswords_NestedEntryFields_ShouldAllBePresent() throws Exception {
        ReusedPasswordResponse.ReusedEntryInfo entry = ReusedPasswordResponse.ReusedEntryInfo.builder()
                .entryId(42L).title("Facebook").username("fb@test.com")
                .websiteUrl("https://facebook.com").build();

        ReusedPasswordResponse response = ReusedPasswordResponse.builder()
                .totalReusedGroups(1).totalAffectedEntries(1)
                .reusedGroups(List.of(
                        ReusedPasswordResponse.ReusedPasswordGroup.builder()
                                .reuseCount(1).entries(List.of(entry)).build()))
                .build();

        when(dashboardService.getReusedPasswords("testuser")).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/reused-passwords"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reusedGroups[0].entries[0].entryId").value(42))
                .andExpect(jsonPath("$.reusedGroups[0].entries[0].title").value("Facebook"))
                .andExpect(jsonPath("$.reusedGroups[0].entries[0].username").value("fb@test.com"))
                .andExpect(jsonPath("$.reusedGroups[0].entries[0].websiteUrl")
                        .value("https://facebook.com"));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getPasswordAge_AllDistributionBuckets_ShouldBeAsserted() throws Exception {
        List<PasswordAgeResponse.AgeDistributionBucket> distribution = List.of(
                PasswordAgeResponse.AgeDistributionBucket.builder().label("< 30 days").count(2)
                        .minDays(0).maxDays(29).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder().label("30-90 days").count(4)
                        .minDays(30).maxDays(90).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder().label("90-180 days").count(3)
                        .minDays(91).maxDays(180).build(),
                PasswordAgeResponse.AgeDistributionBucket.builder().label("> 180 days").count(1)
                        .minDays(181).maxDays(Integer.MAX_VALUE).build());

        when(dashboardService.getPasswordAge("testuser")).thenReturn(
                PasswordAgeResponse.builder().totalPasswords(10).freshCount(2).agingCount(4)
                        .oldCount(3).ancientCount(1).averageAgeInDays(88.0)
                        .distribution(distribution).build());

        mockMvc.perform(get("/api/dashboard/password-age"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.distribution").isArray())
                .andExpect(jsonPath("$.distribution.length()").value(4))
                .andExpect(jsonPath("$.distribution[0].label").value("< 30 days"))
                .andExpect(jsonPath("$.distribution[0].count").value(2))
                .andExpect(jsonPath("$.distribution[0].minDays").value(0))
                .andExpect(jsonPath("$.distribution[0].maxDays").value(29))
                .andExpect(jsonPath("$.distribution[1].label").value("30-90 days"))
                .andExpect(jsonPath("$.distribution[1].count").value(4))
                .andExpect(jsonPath("$.distribution[2].label").value("90-180 days"))
                .andExpect(jsonPath("$.distribution[2].count").value(3))
                .andExpect(jsonPath("$.distribution[3].label").value("> 180 days"))
                .andExpect(jsonPath("$.distribution[3].count").value(1));
    }

    @Test
    @WithMockUser(username = "testuser")
    void getSecurityTrends_TrendPointFields_ShouldAllBePresent() throws Exception {
        SecurityTrendResponse.TrendDataPoint point = SecurityTrendResponse.TrendDataPoint.builder()
                .recordedAt(LocalDateTime.of(2026, 2, 1, 10, 0))
                .overallScore(78)
                .weakPasswordsCount(3)
                .reusedPasswordsCount(2)
                .oldPasswordsCount(1)
                .build();

        SecurityTrendResponse response = SecurityTrendResponse.builder()
                .trendPoints(List.of(point)).scoreChange(8)
                .trendDirection("IMPROVING").periodLabel("30-day trend").build();

        when(dashboardService.getSecurityTrends(eq("testuser"), eq(30))).thenReturn(response);

        mockMvc.perform(get("/api/dashboard/trends"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trendPoints[0].overallScore").value(78))
                .andExpect(jsonPath("$.trendPoints[0].weakPasswordsCount").value(3))
                .andExpect(jsonPath("$.trendPoints[0].reusedPasswordsCount").value(2))
                .andExpect(jsonPath("$.trendPoints[0].oldPasswordsCount").value(1))
                .andExpect(jsonPath("$.trendPoints[0].recordedAt").isNotEmpty());
    }
}
