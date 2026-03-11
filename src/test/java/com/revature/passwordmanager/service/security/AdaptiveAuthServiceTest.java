package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.model.security.LoginAttempt;
import com.revature.passwordmanager.model.security.SecurityAlert;
import com.revature.passwordmanager.repository.LoginAttemptRepository;
import com.revature.passwordmanager.service.security.AdaptiveAuthService;
import com.revature.passwordmanager.service.security.SecurityAlertService;
import com.revature.passwordmanager.util.DateTimeUtil;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdaptiveAuthServiceTest {

  @Mock
  private LoginAttemptRepository loginAttemptRepository;
  @Mock
  private SecurityAlertService securityAlertService;
  @Mock
  private DateTimeUtil dateTimeUtil;

  @InjectMocks
  private AdaptiveAuthService adaptiveAuthService;

  @Test
  void calculateRiskScore_FirstLogin_ShouldReturnHighRisk() {
    when(loginAttemptRepository.findByUsernameAttemptedOrderByTimestampDesc("testuser"))
        .thenReturn(Collections.emptyList());

    int score = adaptiveAuthService.calculateRiskScore("testuser", "1.2.3.4", "Chrome", "Chrome");

    assertTrue(score >= 30);
  }

  @Test
  void calculateRiskScore_KnownIpAndDevice_ShouldReturnLowRisk() {
    LoginAttempt attempt = LoginAttempt.builder()
        .usernameAttempted("testuser")
        .ipAddress("1.2.3.4")
        .deviceInfo("Chrome")
        .successful(true)
        .timestamp(LocalDateTime.now().minusHours(2))
        .build();

    when(loginAttemptRepository.findByUsernameAttemptedOrderByTimestampDesc("testuser"))
        .thenReturn(List.of(attempt));
    when(dateTimeUtil.isUnusualTime(any())).thenReturn(false);

    int score = adaptiveAuthService.calculateRiskScore("testuser", "1.2.3.4", "Chrome", "Chrome");

    assertEquals(0, score);
  }

  @Test
  void calculateRiskScore_NewIp_ShouldFlagAlert() {
    LoginAttempt attempt = LoginAttempt.builder()
        .usernameAttempted("testuser")
        .ipAddress("1.2.3.4")
        .deviceInfo("Chrome")
        .successful(true)
        .timestamp(LocalDateTime.now().minusHours(2))
        .build();

    when(loginAttemptRepository.findByUsernameAttemptedOrderByTimestampDesc("testuser"))
        .thenReturn(List.of(attempt));
    when(dateTimeUtil.isUnusualTime(any())).thenReturn(false);

    int score = adaptiveAuthService.calculateRiskScore("testuser", "5.6.7.8", "Chrome", "Chrome");

    assertTrue(score >= 40);
    verify(securityAlertService).createAlert(eq("testuser"),
        eq(SecurityAlert.AlertType.NEW_LOCATION_LOGIN), anyString(), anyString(), any());
  }

  @Test
  void requiresAdditionalVerification_HighRisk_ShouldReturnTrue() {
    assertTrue(adaptiveAuthService.requiresAdditionalVerification(50));
    assertFalse(adaptiveAuthService.requiresAdditionalVerification(30));
  }
}
