package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.NotificationDTO;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.notification.NotificationService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = NotificationController.class, excludeAutoConfiguration = {
        org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class
})
@Import(SecurityConfig.class)
public class NotificationControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private NotificationService notificationService;

  @MockBean
  private CustomUserDetailsService customUserDetailsService;

  @MockBean
  private JwtTokenProvider jwtTokenProvider;

  @MockBean
  private SessionService sessionService;

  @MockBean
  private RateLimitService rateLimitService;

  @MockBean
  private ClientIpUtil clientIpUtil;

  private NotificationDTO notification1;
  private NotificationDTO notification2;

  @BeforeEach
  void setUp() {
    when(clientIpUtil.getClientIpAddress(org.mockito.ArgumentMatchers.any())).thenReturn("127.0.0.1");
    when(rateLimitService.isAllowed(anyString(), anyString())).thenReturn(true);
    when(rateLimitService.getRemainingRequests(anyString(), anyString())).thenReturn(100);

    notification1 = NotificationDTO.builder()
            .id(1L)
            .notificationType("SECURITY_ALERT")
            .title("Login from new device")
            .message("A login was detected from a new device")
            .isRead(false)
            .createdAt(LocalDateTime.now())
            .build();

    notification2 = NotificationDTO.builder()
            .id(2L)
            .notificationType("PASSWORD_EXPIRY")
            .title("Password expiring soon")
            .message("Your password for Gmail will expire in 7 days")
            .isRead(true)
            .createdAt(LocalDateTime.now())
            .build();
  }

  @Test
  @WithMockUser(username = "testuser")
  void getNotifications_ShouldReturnList() throws Exception {
    when(notificationService.getNotifications("testuser"))
            .thenReturn(List.of(notification1, notification2));

    mockMvc.perform(get("/api/notifications"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[0].id").value(1))
            .andExpect(jsonPath("$[0].notificationType").value("SECURITY_ALERT"))
            .andExpect(jsonPath("$[0].title").value("Login from new device"))
            .andExpect(jsonPath("$[0].message").value("A login was detected from a new device"))
            .andExpect(jsonPath("$[1].id").value(2))
            .andExpect(jsonPath("$[1].notificationType").value("PASSWORD_EXPIRY"))
            .andExpect(jsonPath("$[1].title").value("Password expiring soon"))
            .andExpect(jsonPath("$[1].message").value("Your password for Gmail will expire in 7 days"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void getUnreadCount_ShouldReturnCount() throws Exception {
    when(notificationService.getUnreadCount("testuser")).thenReturn(5L);

    mockMvc.perform(get("/api/notifications/unread-count"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.unreadCount").value(5));
  }

  @Test
  @WithMockUser(username = "testuser")
  void markAsRead_ShouldReturnOk() throws Exception {
    doNothing().when(notificationService).markAsRead("testuser", 1L);

    mockMvc.perform(put("/api/notifications/1/read"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Notification marked as read"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void markAllAsRead_ShouldReturnOk() throws Exception {
    doNothing().when(notificationService).markAllAsRead("testuser");

    mockMvc.perform(put("/api/notifications/mark-all-read"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("All notifications marked as read"));
  }

  @Test
  @WithMockUser(username = "testuser")
  void deleteNotification_ShouldReturnOk() throws Exception {
    doNothing().when(notificationService).deleteNotification("testuser", 1L);

    mockMvc.perform(delete("/api/notifications/1"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Notification deleted"));
  }

  @Test
  void getNotifications_WithoutAuth_ShouldReturnForbidden() throws Exception {
    mockMvc.perform(get("/api/notifications"))
            .andExpect(status().isForbidden());
  }
}
