package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.dto.request.LoginRequest;
import com.revature.passwordmanager.dto.request.RefreshTokenRequest;
import com.revature.passwordmanager.dto.response.AuthResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.security.SecurityAlert.AlertType;
import com.revature.passwordmanager.model.security.SecurityAlert.Severity;
import com.revature.passwordmanager.model.user.SecurityQuestion;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.config.JwtConfig;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.email.EmailService;
import com.revature.passwordmanager.service.security.AdaptiveAuthService;
import com.revature.passwordmanager.service.security.AuditLogService;
import com.revature.passwordmanager.service.security.DuressService;
import com.revature.passwordmanager.service.security.GeoLocationService;
import com.revature.passwordmanager.service.security.LoginAttemptService;
import com.revature.passwordmanager.service.security.SecurityAlertService;
import com.revature.passwordmanager.util.DeviceFingerprintUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private AuthenticationManager authenticationManager;

  @Mock
  private JwtTokenProvider tokenProvider;

  @Mock
  private JwtConfig jwtConfig;

  @Mock
  private SessionService sessionService;

  @Mock
  private SecurityQuestionService securityQuestionService;

  @Mock
  private EmailService emailService;

  @Mock
  private OtpService otpService;

  @Mock
  private AuditLogService auditLogService;

  @Mock
  private LoginAttemptService loginAttemptService;

  @Mock
  private SecurityAlertService securityAlertService;

  @Mock
  private TwoFactorService twoFactorService;

  @Mock
  private AdaptiveAuthService adaptiveAuthService;

  @Mock
  private GeoLocationService geoLocationService;

  @Mock
  private DuressService duressService;

  @Mock
  private DeviceFingerprintUtil deviceFingerprintUtil;

  @InjectMocks
  private AuthenticationService authenticationService;

  private LoginRequest loginRequest;
  private User user;

  @BeforeEach
  void setUp() {
    loginRequest = new LoginRequest();
    loginRequest.setUsername("testuser");
    loginRequest.setMasterPassword("password123");

    user = new User();
    user.setUsername("testuser");
    user.setEmail("test@example.com");
    user.setMasterPasswordHash("hashedPassword");
    user.setEmailVerified(true);
  }

  @Test
  void testLogin_Success() {
    user.setFailedLoginAttempts(1); // Set to 1 to trigger reset logic
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    // Atomic reset mock
    doNothing().when(userRepository).resetFailedLoginAttempts("testuser");

    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(mock(Authentication.class));
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");
    when(jwtConfig.getAccessTokenExpiration()).thenReturn(900000L);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    AuthResponse response = authenticationService.login(loginRequest, mockRequest);

    assertNotNull(response);
    assertEquals("accessToken", response.getAccessToken());
    assertEquals("refreshToken", response.getRefreshToken());
    assertEquals("testuser", response.getUsername());
    assertEquals(900000L, response.getExpiresIn());
    assertFalse(response.isRequires2FA());

    verify(sessionService).createSession(eq(user), eq("accessToken"), eq(mockRequest), any(), any());
    verify(userRepository).resetFailedLoginAttempts("testuser");
  }

  @Test
  void testLogin_UserNotFound() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.empty());
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    jakarta.servlet.http.HttpServletRequest mockRequest = mock(jakarta.servlet.http.HttpServletRequest.class);
    assertThrows(AuthenticationException.class, () -> authenticationService.login(loginRequest, mockRequest));
  }

  @Test
  void testRefreshToken_Success() {
    RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
    refreshRequest.setRefreshToken("validRefreshToken");

    when(tokenProvider.validateToken("validRefreshToken")).thenReturn(true);
    when(tokenProvider.getUsernameFromToken("validRefreshToken")).thenReturn("testuser");
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("newAccessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("newRefreshToken");
    when(jwtConfig.getAccessTokenExpiration()).thenReturn(900000L);

    jakarta.servlet.http.HttpServletRequest mockRequest = mock(jakarta.servlet.http.HttpServletRequest.class);
    AuthResponse response = authenticationService.refreshToken(refreshRequest, mockRequest);

    assertNotNull(response);
    assertEquals("newAccessToken", response.getAccessToken());
    assertEquals("newRefreshToken", response.getRefreshToken());
    assertEquals("testuser", response.getUsername());
    assertEquals(900000L, response.getExpiresIn());

    verify(sessionService).createSession(eq(user), eq("newAccessToken"), eq(mockRequest), any(), any());
  }

  @Test
  void testRefreshToken_Invalid() {
    RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
    refreshRequest.setRefreshToken("invalidToken");

    when(tokenProvider.validateToken("invalidToken")).thenReturn(false);

    jakarta.servlet.http.HttpServletRequest mockRequest = mock(jakarta.servlet.http.HttpServletRequest.class);
    assertThrows(AuthenticationException.class, () -> authenticationService.refreshToken(refreshRequest, mockRequest));
  }

  @Test
  void testLogout() {
    String authHeader = "Bearer validAccessToken";
    authenticationService.logout(authHeader, "testuser");
    verify(sessionService).terminateSessionByToken("validAccessToken");
  }

  @Test
  void testLogout_InvalidHeader() {
    authenticationService.logout(null, "testuser");
    verify(sessionService, never()).terminateSessionByToken(anyString());

    authenticationService.logout("InvalidHeader", "testuser");
    verify(sessionService, never()).terminateSessionByToken(anyString());
  }

  @Test
  void testGetSecurityQuestions_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    SecurityQuestion sq = new SecurityQuestion();
    sq.setQuestionText("Q1");
    when(securityQuestionService.getSecurityQuestions(user)).thenReturn(Collections.singletonList(sq));

    List<SecurityQuestionDTO> result = authenticationService
        .getSecurityQuestions("testuser");

    assertNotNull(result);
    assertEquals(1, result.size());
    assertEquals("Q1", result.get(0).getQuestion());
  }

  @Test
  void testSendOtp_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(otpService.generateOtp(user, "EMAIL")).thenReturn("123456");

    authenticationService.sendOtp("testuser");

    verify(emailService).sendOtpEmail("test@example.com", "123456");
  }

  @Test
  void testLogin_FailedAttempt_TriggersMultipleFailedLoginsAlert() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    // Mock atomic DB fetch
    User postIncrementUser = new User();
    postIncrementUser.setUsername("testuser");
    postIncrementUser.setEmail("test@example.com");
    postIncrementUser.setFailedLoginAttempts(3); // Resulting count after increment
    when(userRepository.findById(any())).thenReturn(Optional.of(postIncrementUser));

    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.1");
    when(mockRequest.getHeader("User-Agent")).thenReturn("TestBrowser");

    assertThrows(AuthenticationException.class,
        () -> authenticationService.login(loginRequest, mockRequest));

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.MULTIPLE_FAILED_LOGINS),
        eq("Multiple Failed Login Attempts"),
        contains("3 failed login attempts"),
        eq(Severity.HIGH));
  }

  @Test
  void testLogin_FailedAttempt_TriggersAccountLockedAlert() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    // Mock atomic DB fetch
    User postIncrementUser = new User();
    postIncrementUser.setUsername("testuser");
    postIncrementUser.setEmail("test@example.com");
    postIncrementUser.setFailedLoginAttempts(5); // Resulting count after increment causes lockout
    postIncrementUser.setLockoutCount(0);
    when(userRepository.findById(any())).thenReturn(Optional.of(postIncrementUser));

    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    when(mockRequest.getRemoteAddr()).thenReturn("192.168.1.1");
    when(mockRequest.getHeader("User-Agent")).thenReturn("TestBrowser");

    assertThrows(AuthenticationException.class,
        () -> authenticationService.login(loginRequest, mockRequest));

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.MULTIPLE_FAILED_LOGINS),
        eq("Multiple Failed Login Attempts"),
        anyString(),
        eq(Severity.HIGH));

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.ACCOUNT_LOCKED),
        eq("Account Locked"),
        contains("15 minutes"),
        eq(Severity.CRITICAL));
  }

  @Test
  void testLogin_Success_RecordsAttemptButNoAlert() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(mock(Authentication.class));
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");
    when(jwtConfig.getAccessTokenExpiration()).thenReturn(900000L);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    authenticationService.login(loginRequest, mockRequest);

    verify(loginAttemptService).recordLoginAttempt(
        eq("testuser"), eq(true), isNull(), any(), any(), any(), anyInt());

    verify(securityAlertService, never()).createAlert(
        anyString(), any(AlertType.class), anyString(), anyString(), any(Severity.class));
  }

  @Test
  void testLogin_TwoFailedAttempts_NoAlertTriggered() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    // Mock atomic DB fetch
    User postIncrementUser = new User();
    postIncrementUser.setUsername("testuser");
    postIncrementUser.setEmail("test@example.com");
    postIncrementUser.setFailedLoginAttempts(2); // Resulting count after increment
    when(userRepository.findById(any())).thenReturn(Optional.of(postIncrementUser));

    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);

    assertThrows(AuthenticationException.class,
        () -> authenticationService.login(loginRequest, mockRequest));

    verify(userRepository).incrementFailedLoginAttempts("testuser");

    verify(securityAlertService, never()).createAlert(
        anyString(), any(AlertType.class), anyString(), anyString(), any(Severity.class));
  }

  @Test
  void testVerifyOtp_Success() {
    user.set2faEnabled(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(twoFactorService.verifyCode(user, "123456")).thenReturn(true);
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");
    when(jwtConfig.getAccessTokenExpiration()).thenReturn(900000L);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    AuthResponse response = authenticationService.verifyOtp("testuser", "123456", mockRequest);

    assertNotNull(response);
    assertEquals("accessToken", response.getAccessToken());
    assertFalse(response.isRequires2FA());
    verify(sessionService).createSession(eq(user), eq("accessToken"), eq(mockRequest), any(), any());
    verify(auditLogService).logAction(eq("testuser"), any(), anyString(), any());
    verify(loginAttemptService).recordLoginAttempt(eq("testuser"), eq(true), isNull(), any(), any(), any(), anyInt());
  }

  @Test
  void testVerifyOtp_2FaNotEnabled() {
    user.set2faEnabled(false);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    assertThrows(AuthenticationException.class,
        () -> authenticationService.verifyOtp("testuser", "123456", mockRequest));
  }

  @Test
  void testVerifyOtp_InvalidCode() {
    user.set2faEnabled(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(twoFactorService.verifyCode(user, "123456")).thenReturn(false);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    assertThrows(AuthenticationException.class,
        () -> authenticationService.verifyOtp("testuser", "123456", mockRequest));
  }

  @Test
  void testRefreshToken_UserNotFound() {
    RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
    refreshRequest.setRefreshToken("validRefreshToken");

    when(tokenProvider.validateToken("validRefreshToken")).thenReturn(true);
    when(tokenProvider.getUsernameFromToken("validRefreshToken")).thenReturn("unknownUser");
    when(userRepository.findByUsernameOrThrow("unknownUser"))
        .thenThrow(new com.revature.passwordmanager.exception.ResourceNotFoundException("User not found"));

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    assertThrows(com.revature.passwordmanager.exception.ResourceNotFoundException.class,
        () -> authenticationService.refreshToken(refreshRequest, mockRequest));
  }

  @Test
  void testLogin_AccountAlreadyLocked_RecordsAttempt() {
    user.setLockedUntil(java.time.LocalDateTime.now().plusMinutes(15));
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(userRepository.findByEmail(loginRequest.getUsername())).thenReturn(Optional.empty());

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
    // Mock header to avoid NPE if code checks it
    when(mockRequest.getHeader("User-Agent")).thenReturn("TestAgent");

    assertThrows(AuthenticationException.class, () -> authenticationService.login(loginRequest, mockRequest));

    verify(loginAttemptService).recordLoginAttempt(
        eq("testuser"),
        eq(false),
        eq("Account locked"),
        eq("127.0.0.1"),
        any(),
        any(),
        anyInt());
  }

  @Test
  void testLogin_EmailNotVerified() {
    user.setEmailVerified(false);
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    AuthenticationException ex = assertThrows(AuthenticationException.class,
        () -> authenticationService.login(loginRequest, mockRequest));
    assertTrue(ex.getMessage().contains("Email not verified"));
  }

  @Test
  void testLogin_Success_NewDevice_TriggersAlert() {
    when(userRepository.findByUsername(loginRequest.getUsername())).thenReturn(Optional.of(user));
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(mock(Authentication.class));
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");

    // Stub isNewDevice to return true
    when(loginAttemptService.isNewDevice(eq("testuser"), any())).thenReturn(true);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    when(mockRequest.getHeader("User-Agent")).thenReturn("NewDevice");

    authenticationService.login(loginRequest, mockRequest);

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.NEW_DEVICE_LOGIN),
        anyString(),
        contains("NewDevice"),
        eq(Severity.MEDIUM));
  }

  @Test
  void testVerifyOtp_Success_NewDevice_TriggersAlert() {
    user.set2faEnabled(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(twoFactorService.verifyCode(user, "123456")).thenReturn(true);
    when(tokenProvider.generateAccessToken(any(Authentication.class))).thenReturn("accessToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");

    when(loginAttemptService.isNewDevice(eq("testuser"), any())).thenReturn(true);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    when(mockRequest.getHeader("User-Agent")).thenReturn("NewDevice");

    authenticationService.verifyOtp("testuser", "123456", mockRequest);

    verify(securityAlertService).createAlert(
        eq("testuser"),
        eq(AlertType.NEW_DEVICE_LOGIN),
        anyString(),
        contains("NewDevice"),
        eq(Severity.MEDIUM));
  }

  @Test
  void testDuressLogin_Success() {
    when(duressService.isDuressLogin("testuser", "password123")).thenReturn(true);
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(tokenProvider.generateDuressToken(any(Authentication.class))).thenReturn("duressToken");
    when(tokenProvider.generateRefreshToken(any(Authentication.class))).thenReturn("refreshToken");
    when(jwtConfig.getAccessTokenExpiration()).thenReturn(900000L);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    AuthResponse response = authenticationService.duressLogin(loginRequest, mockRequest);

    assertNotNull(response);
    assertEquals("duressToken", response.getAccessToken());
    verify(sessionService).createSession(eq(user), eq("duressToken"), eq(mockRequest), any(), any());
  }

  @Test
  void testDuressLogin_InvalidCredentials() {
    when(duressService.isDuressLogin("testuser", "password123")).thenReturn(false);

    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    assertThrows(AuthenticationException.class, () -> authenticationService.duressLogin(loginRequest, mockRequest));
  }
}
