package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.SecurityAlertDTO;
import com.revature.passwordmanager.dto.response.AuditLogResponse;
import com.revature.passwordmanager.dto.response.LoginHistoryResponse;
import com.revature.passwordmanager.dto.response.SecurityAuditResponse;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.AuditLogService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import com.revature.passwordmanager.service.security.LoginAttemptService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.service.security.SecurityAlertService;
import com.revature.passwordmanager.service.security.SecurityAuditService;
import com.revature.passwordmanager.util.ClientIpUtil;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = SecurityController.class, excludeAutoConfiguration = {
        org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class
})
class SecurityControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private AuditLogService auditLogService;

        @MockBean
        private JwtTokenProvider jwtTokenProvider;

        @MockBean
        private CustomUserDetailsService customUserDetailsService;

        @MockBean
        private SessionService sessionService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private LoginAttemptService loginAttemptService;

        @MockBean
        private SecurityAlertService securityAlertService;

        @MockBean
        private SecurityAuditService securityAuditService;

        @MockBean
        private ClientIpUtil clientIpUtil;

        @org.junit.jupiter.api.BeforeEach
        void setUp() {
                org.mockito.Mockito.when(clientIpUtil.getClientIpAddress(org.mockito.ArgumentMatchers.any()))
                        .thenReturn("127.0.0.1");
                org.mockito.Mockito.when(
                                rateLimitService.isAllowed(org.mockito.ArgumentMatchers.anyString(),
                                        org.mockito.ArgumentMatchers.anyString()))
                        .thenReturn(true);
                org.mockito.Mockito.when(rateLimitService.getRemainingRequests(org.mockito.ArgumentMatchers.anyString(),
                        org.mockito.ArgumentMatchers.anyString())).thenReturn(100);
        }

        @Test
        @WithMockUser(username = "testuser")
        void getAuditLogs_ShouldReturnList() throws Exception {
                AuditLogResponse log = AuditLogResponse.builder()
                        .id(1L)
                        .action("LOGIN")
                        .details("Successful login")
                        .ipAddress("127.0.0.1")
                        .timestamp(LocalDateTime.of(2026, 1, 15, 10, 0))
                        .build();

                when(auditLogService.getAuditLogs("testuser")).thenReturn(List.of(log));

                mockMvc.perform(get("/api/security/audit-logs"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].action").value("LOGIN"))
                        .andExpect(jsonPath("$[0].details").value("Successful login"))
                        .andExpect(jsonPath("$[0].ipAddress").value("127.0.0.1"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getLoginHistory_ShouldReturnList() throws Exception {
                LoginHistoryResponse entry = LoginHistoryResponse.builder()
                        .id(1L)
                        .ipAddress("192.168.1.1")
                        .deviceInfo("Chrome on Windows")
                        .location("New York")
                        .successful(true)
                        .timestamp(LocalDateTime.of(2026, 1, 15, 10, 0))
                        .build();

                when(loginAttemptService.getLoginHistory("testuser")).thenReturn(List.of(entry));

                mockMvc.perform(get("/api/security/login-history"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].ipAddress").value("192.168.1.1"))
                        .andExpect(jsonPath("$[0].deviceInfo").value("Chrome on Windows"))
                        .andExpect(jsonPath("$[0].location").value("New York"))
                        .andExpect(jsonPath("$[0].successful").value(true));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getAlerts_ShouldReturnList() throws Exception {
                SecurityAlertDTO alert = SecurityAlertDTO.builder()
                        .id(1L)
                        .alertType("SUSPICIOUS_LOGIN")
                        .title("Suspicious Login Attempt")
                        .message("Login from unknown device")
                        .severity("HIGH")
                        .isRead(false)
                        .createdAt(LocalDateTime.of(2026, 1, 15, 10, 0))
                        .build();

                when(securityAlertService.getAlerts("testuser")).thenReturn(List.of(alert));

                mockMvc.perform(get("/api/security/alerts"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].alertType").value("SUSPICIOUS_LOGIN"))
                        .andExpect(jsonPath("$[0].title").value("Suspicious Login Attempt"))
                        .andExpect(jsonPath("$[0].message").value("Login from unknown device"))
                        .andExpect(jsonPath("$[0].severity").value("HIGH"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void markAlertAsRead_ShouldReturnOk() throws Exception {
                doNothing().when(securityAlertService).markAsRead("testuser", 1L);

                mockMvc.perform(put("/api/security/alerts/1/read")
                                .with(csrf()))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.message").value("Alert marked as read"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void deleteAlert_ShouldReturnOk() throws Exception {
                doNothing().when(securityAlertService).deleteAlert("testuser", 1L);

                mockMvc.perform(delete("/api/security/alerts/1")
                                .with(csrf()))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.message").value("Alert deleted"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getAuditReport_ShouldReturnReport() throws Exception {
                SecurityAuditResponse report = SecurityAuditResponse.builder()
                        .totalEntries(50)
                        .weakCount(5)
                        .reusedCount(3)
                        .oldCount(10)
                        .securityScore(75)
                        .recommendations(List.of("Update weak passwords"))
                        .weakPasswords(Collections.emptyList())
                        .reusedPasswords(Collections.emptyList())
                        .oldPasswords(Collections.emptyList())
                        .build();

                when(securityAuditService.generateAuditReport("testuser")).thenReturn(report);

                mockMvc.perform(get("/api/security/audit-report"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalEntries").value(50))
                        .andExpect(jsonPath("$.securityScore").value(75))
                        .andExpect(jsonPath("$.weakCount").value(5))
                        .andExpect(jsonPath("$.reusedCount").value(3))
                        .andExpect(jsonPath("$.oldCount").value(10))
                        .andExpect(jsonPath("$.recommendations[0]").value("Update weak passwords"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getWeakPasswords_ShouldReturnList() throws Exception {
                SecurityAuditResponse.VaultEntrySummary summary = SecurityAuditResponse.VaultEntrySummary.builder()
                        .id(1L)
                        .title("Weak Entry")
                        .issue("Weak password (score: 50/100)")
                        .build();

                when(securityAuditService.getWeakPasswords("testuser")).thenReturn(List.of(summary));

                mockMvc.perform(get("/api/security/weak-passwords"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Weak Entry"))
                        .andExpect(jsonPath("$[0].issue").value("Weak password (score: 50/100)"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getReusedPasswords_ShouldReturnList() throws Exception {
                SecurityAuditResponse.VaultEntrySummary summary = SecurityAuditResponse.VaultEntrySummary.builder()
                        .id(2L)
                        .title("Reused Entry")
                        .issue("Password is reused")
                        .build();

                when(securityAuditService.getReusedPasswords("testuser")).thenReturn(List.of(summary));

                mockMvc.perform(get("/api/security/reused-passwords"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(2))
                        .andExpect(jsonPath("$[0].title").value("Reused Entry"))
                        .andExpect(jsonPath("$[0].issue").value("Password is reused"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getOldPasswords_ShouldReturnList() throws Exception {
                SecurityAuditResponse.VaultEntrySummary summary = SecurityAuditResponse.VaultEntrySummary.builder()
                        .id(3L)
                        .title("Old Entry")
                        .issue("Password not updated in over 90 days")
                        .build();

                when(securityAuditService.getOldPasswords("testuser")).thenReturn(List.of(summary));

                mockMvc.perform(get("/api/security/old-passwords"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(3))
                        .andExpect(jsonPath("$[0].title").value("Old Entry"))
                        .andExpect(jsonPath("$[0].issue").value("Password not updated in over 90 days"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void analyzeVault_ShouldReturnReport() throws Exception {
                SecurityAuditResponse report = SecurityAuditResponse.builder()
                        .totalEntries(10)
                        .securityScore(90)
                        .build();

                when(securityAuditService.generateAuditReport("testuser")).thenReturn(report);

                mockMvc.perform(post("/api/security/analyze-vault").with(csrf()))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalEntries").value(10))
                        .andExpect(jsonPath("$.securityScore").value(90));
        }
}
