package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.request.RegistrationRequest;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.email.EmailService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private SecurityQuestionService securityQuestionService;

  @Mock
  private OtpService otpService;

  @Mock
  private EmailService emailService;

  @Mock
  private FolderRepository folderRepository;

  @Mock
  private CategoryRepository categoryRepository;

  @InjectMocks
  private RegistrationService registrationService;

  private RegistrationRequest request;

  @BeforeEach
  void setUp() {
    request = new RegistrationRequest();
    request.setUsername("testuser");
    request.setEmail("test@example.com");
    request.setMasterPassword("StrongPassword123!");
  }

  @Test
  void testRegisterUser_Success() {
    request.setPasswordHint("My favorite color");

    when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
    when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
    when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
    when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
      User user = invocation.getArgument(0);
      assertNotNull(user.getSalt(), "Salt must not be null");
      assertEquals("My favorite color", user.getPasswordHint());
      assertFalse(user.getEmailVerified(), "emailVerified should be false on registration");
      user.setId(1L);
      return user;
    });
    when(otpService.generateOtp(any(User.class), eq("EMAIL_VERIFICATION"))).thenReturn("123456");

    UserResponse response = registrationService.registerUser(request);

    assertNotNull(response);
    assertEquals(1L, response.getId());
    assertEquals(request.getUsername(), response.getUsername());
    assertEquals(request.getEmail(), response.getEmail());
    assertFalse(response.is2faEnabled());
    assertNotNull(response.getCreatedAt());

    verify(userRepository).save(any(User.class));
    verify(securityQuestionService).saveSecurityQuestions(any(User.class), any());
    verify(otpService).generateOtp(any(User.class), eq("EMAIL_VERIFICATION"));
    verify(emailService).sendOtpEmail(eq("test@example.com"), eq("123456"));
  }

  @Test
  void testRegisterUser_DuplicateUsername() {
    when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
    when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);

    assertThrows(AuthenticationException.class, () -> registrationService.registerUser(request));
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void testRegisterUser_DuplicateEmail() {
    when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

    assertThrows(AuthenticationException.class, () -> registrationService.registerUser(request));
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void testRegisterUser_HintContainsPassword() {
    request.setPasswordHint("My password is StrongPassword123!");

    when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
    when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);

    AuthenticationException exception = assertThrows(AuthenticationException.class,
        () -> registrationService.registerUser(request));
    assertEquals("Password hint cannot contain the master password", exception.getMessage());
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void testVerifyEmail_Success() {
    User user = new User();
    user.setUsername("testuser");
    user.setEmailVerified(false);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(otpService.validateOtp(user, "123456", "EMAIL_VERIFICATION")).thenReturn(true);

    registrationService.verifyEmail("testuser", "123456");

    assertTrue(user.getEmailVerified());
    verify(userRepository).save(user);
  }

  @Test
  void testVerifyEmail_AlreadyVerified() {
    User user = new User();
    user.setUsername("testuser");
    user.setEmailVerified(true);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

    assertThrows(AuthenticationException.class,
        () -> registrationService.verifyEmail("testuser", "123456"));
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void testVerifyEmail_UserNotFound() {
    when(userRepository.findByUsername("unknownuser")).thenReturn(Optional.empty());
    when(userRepository.findByEmail("unknownuser")).thenReturn(Optional.empty());

    assertThrows(AuthenticationException.class,
        () -> registrationService.verifyEmail("unknownuser", "123456"));
  }

  @Test
  void testResendVerificationOtp_Success() {
    User user = new User();
    user.setUsername("testuser");
    user.setEmail("test@example.com");
    user.setEmailVerified(false);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(otpService.generateOtp(user, "EMAIL_VERIFICATION")).thenReturn("654321");

    registrationService.resendVerificationOtp("testuser");

    verify(otpService).generateOtp(user, "EMAIL_VERIFICATION");
    verify(emailService).sendOtpEmail("test@example.com", "654321");
  }

  @Test
  void testResendVerificationOtp_AlreadyVerified() {
    User user = new User();
    user.setUsername("testuser");
    user.setEmailVerified(true);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

    assertThrows(AuthenticationException.class,
        () -> registrationService.resendVerificationOtp("testuser"));
    verify(otpService, never()).generateOtp(any(), anyString());
  }
}
