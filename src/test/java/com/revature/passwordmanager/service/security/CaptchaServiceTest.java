package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.config.CaptchaConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CaptchaServiceTest {

  @Mock
  private CaptchaConfig captchaConfig;

  @Mock
  private LoginAttemptService loginAttemptService;

  @InjectMocks
  private CaptchaService captchaService;

  @Test
  void isCaptchaRequired_WhenDisabled_ShouldReturnFalse() {
    when(captchaConfig.isEnabled()).thenReturn(false);

    assertFalse(captchaService.isCaptchaRequired("testuser"));
  }

  @Test
  void isCaptchaRequired_WhenEnabled_BelowThreshold_ShouldReturnFalse() {
    when(captchaConfig.isEnabled()).thenReturn(true);
    when(captchaConfig.getFailedAttemptsThreshold()).thenReturn(3);
    when(loginAttemptService.getRecentFailedAttempts("testuser", 30)).thenReturn(2L);

    assertFalse(captchaService.isCaptchaRequired("testuser"));
  }

  @Test
  void isCaptchaRequired_WhenEnabled_AboveThreshold_ShouldReturnTrue() {
    when(captchaConfig.isEnabled()).thenReturn(true);
    when(captchaConfig.getFailedAttemptsThreshold()).thenReturn(3);
    when(loginAttemptService.getRecentFailedAttempts("testuser", 30)).thenReturn(5L);

    assertTrue(captchaService.isCaptchaRequired("testuser"));
  }

  @Test
  void verifyCaptcha_WhenDisabled_ShouldReturnTrue() {
    when(captchaConfig.isEnabled()).thenReturn(false);

    assertTrue(captchaService.verifyCaptcha("any-token"));
  }

  @Test
  void verifyCaptcha_WhenEnabled_NullToken_ShouldReturnFalse() {
    when(captchaConfig.isEnabled()).thenReturn(true);

    assertFalse(captchaService.verifyCaptcha(null));
  }

  @Test
  void verifyCaptcha_WhenEnabled_BlankToken_ShouldReturnFalse() {
    when(captchaConfig.isEnabled()).thenReturn(true);

    assertFalse(captchaService.verifyCaptcha("   "));
  }

  @Test
  void verifyCaptcha_WhenEnabled_ValidToken_ShouldReturnTrue() {
    when(captchaConfig.isEnabled()).thenReturn(true);

    assertTrue(captchaService.verifyCaptcha("valid-captcha-token"));
  }
}
