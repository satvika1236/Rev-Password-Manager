package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.response.TwoFactorSetupResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.auth.TwoFactorAuth;
import com.revature.passwordmanager.model.security.SecurityAlert.AlertType;
import com.revature.passwordmanager.model.security.SecurityAlert.Severity;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.TwoFactorAuthRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.SecurityAlertService;
import com.revature.passwordmanager.util.TOTPUtil;
import dev.samstevens.totp.exceptions.QrGenerationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.List;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class TwoFactorServiceTest {

  @Mock
  private TwoFactorAuthRepository twoFactorAuthRepository;

  @Mock
  private UserRepository userRepository;

  @Mock
  private TOTPUtil totpUtil;

  @Mock
  private OtpService otpService;

  @Mock
  private SecurityAlertService securityAlertService;

  @InjectMocks
  private TwoFactorService twoFactorService;

  private User user;
  private TwoFactorAuth twoFactorAuth;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setId(1L);
    user.setUsername("testuser");
    user.setEmail("test@example.com");

    twoFactorAuth = TwoFactorAuth.builder()
        .user(user)
        .secretKey("secret")
        .isEnabled(true)
        .recoveryCodes(new ArrayList<>())
        .build();
  }

  @Test
  void setup2FA_Success() throws QrGenerationException {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.empty());
    when(totpUtil.generateSecret()).thenReturn("new-secret");
    when(totpUtil.getQrCodeUrl(anyString(), anyString())).thenReturn("qr-url");
    when(twoFactorAuthRepository.save(any(TwoFactorAuth.class))).thenReturn(twoFactorAuth);

    TwoFactorSetupResponse response = twoFactorService.setup2FA(user);

    assertNotNull(response);
    assertEquals("new-secret", response.getSecretKey());
    assertEquals("qr-url", response.getQrCodeUrl());
    verify(twoFactorAuthRepository).save(any(TwoFactorAuth.class));
  }

  @Test
  void verifySetup_Success() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(true);

    twoFactorService.verifySetup(user, "123456");

    assertTrue(twoFactorAuth.isEnabled());
    verify(userRepository).save(user);
  }

  @Test
  void verifySetup_InvalidCode() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(false);

    assertThrows(AuthenticationException.class, () -> twoFactorService.verifySetup(user, "wrong"));
  }

  @Test
  void disable2FA_Success() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));

    twoFactorService.disable2FA(user);

    assertFalse(user.is2faEnabled());
    verify(twoFactorAuthRepository).delete(twoFactorAuth);
    verify(userRepository).save(user);
  }

  @Test
  void verifySetup_Success_TriggersEnabledAlert() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(true);

    twoFactorService.verifySetup(user, "123456");

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.TWO_FA_ENABLED),
        eq("Two-Factor Authentication Enabled"),
        eq("2FA has been successfully enabled for your account"),
        eq(Severity.LOW));
  }

  @Test
  void disable2FA_Success_TriggersDisabledAlert() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));

    twoFactorService.disable2FA(user);

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.TWO_FA_DISABLED),
        eq("Two-Factor Authentication Disabled"),
        contains("2FA has been disabled"),
        eq(Severity.HIGH));
  }

  @Test
  void verifySetup_InvalidCode_NoAlertTriggered() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(false);

    assertThrows(AuthenticationException.class,
        () -> twoFactorService.verifySetup(user, "wrong"));

    verify(securityAlertService, never()).createAlert(
        anyString(), any(AlertType.class), anyString(), anyString(), any(Severity.class));
  }

  @Test
  void regenerateRecoveryCodes_Success() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));

    List<String> newCodes = twoFactorService.regenerateRecoveryCodes(user);

    assertNotNull(newCodes);
    assertEquals(10, newCodes.size());
    verify(twoFactorAuthRepository).save(any(TwoFactorAuth.class));
    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.PASSWORD_CHANGED),
        eq("Backup Codes Regenerated"),
        contains("Your 2FA backup codes have been regenerated"),
        eq(Severity.MEDIUM));
  }

  @Test
  void regenerateRecoveryCodes_FailsIfUnverified() {
    twoFactorAuth.setEnabled(false);
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));

    assertThrows(AuthenticationException.class,
        () -> twoFactorService.regenerateRecoveryCodes(user));

    verify(twoFactorAuthRepository, never()).save(any());
  }

  @Test
  void verifyCode_TotpSuccess() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode("secret", "123456")).thenReturn(true);

    boolean result = twoFactorService.verifyCode(user, "123456");

    assertTrue(result);
    verify(totpUtil).verifyCode("secret", "123456");
  }

  @Test
  void verifyCode_RecoveryCodeSuccess() {
    twoFactorAuth.setRecoveryCodes(new ArrayList<>(List.of("RECOVERY1", "RECOVERY2")));
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(false);

    boolean result = twoFactorService.verifyCode(user, "RECOVERY1");

    assertTrue(result);
    assertFalse(twoFactorAuth.getRecoveryCodes().contains("RECOVERY1"));
    verify(twoFactorAuthRepository).save(twoFactorAuth);
  }

  @Test
  void verifyCode_InvalidCode_ReturnsFalse() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));
    when(totpUtil.verifyCode(anyString(), anyString())).thenReturn(false);

    boolean result = twoFactorService.verifyCode(user, "000000");

    assertFalse(result);
  }

  @Test
  void verifyCode_2FANotSetUp_ThrowsException() {
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.empty());

    assertThrows(AuthenticationException.class,
        () -> twoFactorService.verifyCode(user, "123456"));
  }

  @Test
  void verifyCode_2FADisabled_ReturnsFalse() {
    twoFactorAuth.setEnabled(false);
    when(twoFactorAuthRepository.findByUser(user)).thenReturn(Optional.of(twoFactorAuth));

    boolean result = twoFactorService.verifyCode(user, "123456");

    assertFalse(result);
    verify(totpUtil, never()).verifyCode(anyString(), anyString());
  }
}
