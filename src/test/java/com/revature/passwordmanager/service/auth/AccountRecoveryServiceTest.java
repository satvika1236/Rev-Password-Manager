package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.dto.request.RecoveryRequest;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.auth.AccountRecoveryService;
import com.revature.passwordmanager.service.auth.SecurityQuestionService;
import com.revature.passwordmanager.service.auth.SessionService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccountRecoveryServiceTest {

  @Mock
  private UserRepository userRepository;
  @Mock
  private SecurityQuestionService securityQuestionService;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private SessionService sessionService;

  @InjectMocks
  private AccountRecoveryService accountRecoveryService;

  private User user;
  private RecoveryRequest recoveryRequest;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setUsername("testuser");
    user.setEmail("test@example.com");
    user.setMasterPasswordHash("oldHash");

    recoveryRequest = new RecoveryRequest();
    recoveryRequest.setUsername("testuser");
    recoveryRequest.setNewMasterPassword("newPassword123!");
    recoveryRequest.setSecurityAnswers(Collections.singletonList(new SecurityQuestionDTO("Q", "A")));
  }

  @Test
  void testResetPassword_Success() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(securityQuestionService.verifySecurityAnswers(any(User.class), any())).thenReturn(true);
    when(passwordEncoder.encode("newPassword123!")).thenReturn("newHash");

    accountRecoveryService.resetPassword(recoveryRequest);

    verify(userRepository).save(user);
    verify(sessionService).terminateAllUserSessions("testuser");
    assertEquals("newHash", user.getMasterPasswordHash());
  }

  @Test
  void testResetPassword_InvalidAnswers() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(securityQuestionService.verifySecurityAnswers(any(User.class), any())).thenReturn(false);

    assertThrows(AuthenticationException.class, () -> accountRecoveryService.resetPassword(recoveryRequest));
    verify(userRepository, never()).save(any(User.class));
  }
}
