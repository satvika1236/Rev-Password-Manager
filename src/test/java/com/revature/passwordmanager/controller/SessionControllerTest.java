package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.response.SessionResponse;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = SessionController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class
})
@Import(SecurityConfig.class)
public class SessionControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private SessionService sessionService;

  @MockBean
  private CustomUserDetailsService customUserDetailsService;

  @MockBean
  private JwtTokenProvider jwtTokenProvider;

  @MockBean
  private RateLimitService rateLimitService;

  @MockBean
  private ClientIpUtil clientIpUtil;

  private SessionResponse session1;
  private SessionResponse session2;

  @BeforeEach
  void setUp() {
    Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
    when(rateLimitService.isAllowed(anyString(), anyString())).thenReturn(true);
    when(rateLimitService.getRemainingRequests(anyString(), anyString())).thenReturn(100);

    session1 = SessionResponse.builder()
            .id(1L)
            .ipAddress("192.168.1.1")
            .deviceInfo("Chrome on Windows")
            .location("New York, US")
            .isActive(true)
            .createdAt(LocalDateTime.now().minusHours(2))
            .lastAccessedAt(LocalDateTime.now())
            .expiresAt(LocalDateTime.now().plusHours(6))
            .build();

    session2 = SessionResponse.builder()
            .id(2L)
            .ipAddress("10.0.0.1")
            .deviceInfo("Firefox on Mac")
            .location("London, UK")
            .isActive(true)
            .createdAt(LocalDateTime.now().minusDays(1))
            .lastAccessedAt(LocalDateTime.now().minusHours(1))
            .expiresAt(LocalDateTime.now().plusHours(5))
            .build();
  }

  @Test
  @WithMockUser(username = "testuser")
  void getActiveSessions_ShouldReturnList() throws Exception {
    when(sessionService.getUserSessions("testuser"))
            .thenReturn(List.of(session1, session2));

    mockMvc.perform(get("/api/sessions"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[0].id").value(1))
            .andExpect(jsonPath("$[0].ipAddress").value("192.168.1.1"))
            .andExpect(jsonPath("$[0].deviceInfo").value("Chrome on Windows"))
            .andExpect(jsonPath("$[0].location").value("New York, US"))
            .andExpect(jsonPath("$[1].id").value(2))
            .andExpect(jsonPath("$[1].ipAddress").value("10.0.0.1"))
            .andExpect(jsonPath("$[1].location").value("London, UK"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void getCurrentSession_ShouldReturnSession() throws Exception {
    when(sessionService.getCurrentSession("test-token")).thenReturn(session1);

    mockMvc.perform(get("/api/sessions/current")
                    .header("Authorization", "Bearer test-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(1))
            .andExpect(jsonPath("$.ipAddress").value("192.168.1.1"))
            .andExpect(jsonPath("$.deviceInfo").value("Chrome on Windows"))
            .andExpect(jsonPath("$.location").value("New York, US"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void getCurrentSession_WithoutBearerHeader_ShouldReturnNotFound() throws Exception {
    mockMvc.perform(get("/api/sessions/current")
                    .header("Authorization", "Basic invalid"))
            .andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = "testuser")
  void terminateSession_ShouldReturnNoContent() throws Exception {
    doNothing().when(sessionService).terminateSession(1L, "testuser");

    mockMvc.perform(delete("/api/sessions/1"))
            .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "testuser")
  void terminateAllSessions_ShouldReturnNoContent() throws Exception {
    doNothing().when(sessionService).terminateAllUserSessions("testuser");

    mockMvc.perform(delete("/api/sessions"))
            .andExpect(status().isOk());
  }

  @Test
  void getActiveSessions_WithoutAuth_ShouldReturnForbidden() throws Exception {
    mockMvc.perform(get("/api/sessions"))
            .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "testuser")
  void extendSession_ShouldReturnSession() throws Exception {
    when(sessionService.extendSession("test-token")).thenReturn(session1);

    mockMvc.perform(post("/api/sessions/extend")
                    .header("Authorization", "Bearer test-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(1))
            .andExpect(jsonPath("$.ipAddress").value("192.168.1.1"))
            .andExpect(jsonPath("$.deviceInfo").value("Chrome on Windows"))
            .andExpect(jsonPath("$.location").value("New York, US"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void extendSession_WithoutBearerHeader_ShouldReturnBadRequest() throws Exception {
    mockMvc.perform(post("/api/sessions/extend")
                    .header("Authorization", "Basic invalid"))
            .andExpect(status().isBadRequest());
  }
}
