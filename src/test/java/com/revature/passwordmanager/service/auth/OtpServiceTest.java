package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.auth.OtpToken;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.OtpTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

  @Mock
  private OtpTokenRepository otpTokenRepository;

  @InjectMocks
  private OtpService otpService;

  private User user;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .username("testuser")
        .masterPasswordHash("hash")
        .salt("salt")
        .build();
  }

  @Test
  void generateOtp_ShouldReturn6DigitCode() {
    when(otpTokenRepository.save(any(OtpToken.class))).thenAnswer(i -> i.getArgument(0));

    String otp = otpService.generateOtp(user, "LOGIN");

    assertNotNull(otp);
    assertEquals(6, otp.length());
    assertTrue(otp.matches("\\d{6}"));
  }

  @Test
  void generateOtp_ShouldSaveTokenToRepository() {
    when(otpTokenRepository.save(any(OtpToken.class))).thenAnswer(i -> i.getArgument(0));

    otpService.generateOtp(user, "LOGIN");

    ArgumentCaptor<OtpToken> captor = ArgumentCaptor.forClass(OtpToken.class);
    verify(otpTokenRepository).save(captor.capture());

    OtpToken saved = captor.getValue();
    assertEquals(user, saved.getUser());
    assertEquals("LOGIN", saved.getTokenType());
    assertFalse(saved.isUsed());
    assertNotNull(saved.getExpiryDate());
    assertTrue(saved.getExpiryDate().isAfter(LocalDateTime.now()));
  }

  @Test
  void validateOtp_Success() {
    OtpToken otpToken = OtpToken.builder()
        .id(1L)
        .user(user)
        .token("123456")
        .tokenType("LOGIN")
        .expiryDate(LocalDateTime.now().plusMinutes(10))
        .isUsed(false)
        .build();

    when(otpTokenRepository.findByToken("123456")).thenReturn(Optional.of(otpToken));
    when(otpTokenRepository.save(any(OtpToken.class))).thenAnswer(i -> i.getArgument(0));

    boolean result = otpService.validateOtp(user, "123456", "LOGIN");

    assertTrue(result);
    assertTrue(otpToken.isUsed());
    verify(otpTokenRepository).save(otpToken);
  }

  @Test
  void validateOtp_InvalidToken_ShouldThrow() {
    when(otpTokenRepository.findByToken("999999")).thenReturn(Optional.empty());

    assertThrows(AuthenticationException.class,
        () -> otpService.validateOtp(user, "999999", "LOGIN"));
  }

  @Test
  void validateOtp_WrongUser_ShouldThrow() {
    User otherUser = User.builder().id(2L).username("other").build();
    OtpToken otpToken = OtpToken.builder()
        .id(1L)
        .user(otherUser)
        .token("123456")
        .tokenType("LOGIN")
        .expiryDate(LocalDateTime.now().plusMinutes(10))
        .isUsed(false)
        .build();

    when(otpTokenRepository.findByToken("123456")).thenReturn(Optional.of(otpToken));

    assertThrows(AuthenticationException.class,
        () -> otpService.validateOtp(user, "123456", "LOGIN"));
  }

  @Test
  void validateOtp_AlreadyUsed_ShouldThrow() {
    OtpToken otpToken = OtpToken.builder()
        .id(1L)
        .user(user)
        .token("123456")
        .tokenType("LOGIN")
        .expiryDate(LocalDateTime.now().plusMinutes(10))
        .isUsed(true)
        .build();

    when(otpTokenRepository.findByToken("123456")).thenReturn(Optional.of(otpToken));

    assertThrows(AuthenticationException.class,
        () -> otpService.validateOtp(user, "123456", "LOGIN"));
  }

  @Test
  void validateOtp_Expired_ShouldThrow() {
    OtpToken otpToken = OtpToken.builder()
        .id(1L)
        .user(user)
        .token("123456")
        .tokenType("LOGIN")
        .expiryDate(LocalDateTime.now().minusMinutes(1))
        .isUsed(false)
        .build();

    when(otpTokenRepository.findByToken("123456")).thenReturn(Optional.of(otpToken));

    assertThrows(AuthenticationException.class,
        () -> otpService.validateOtp(user, "123456", "LOGIN"));
  }
}
