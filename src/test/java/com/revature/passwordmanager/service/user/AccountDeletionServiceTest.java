package com.revature.passwordmanager.service.user;

import com.revature.passwordmanager.dto.request.AccountDeletionRequest;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.user.AccountDeletionService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccountDeletionServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private AccountDeletionService deletionService;

  private User user;
  private AccountDeletionRequest request;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setUsername("testuser");
    user.setMasterPasswordHash("hashedPassword");

    request = new AccountDeletionRequest();
    request.setMasterPassword("password123");
    request.setConfirmation(true);
  }

  @Test
  void testScheduleDeletion_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(true);

    deletionService.scheduleAccountDeletion("testuser", request);

    assertNotNull(user.getDeletionRequestedAt());
    assertNotNull(user.getDeletionScheduledAt());
    verify(userRepository).save(user);
  }

  @Test
  void testScheduleDeletion_InvalidPassword() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(false);

    assertThrows(AuthenticationException.class, () -> deletionService.scheduleAccountDeletion("testuser", request));
  }

  @Test
  void testCancelDeletion_Success() {
    user.setDeletionScheduledAt(LocalDateTime.now().plusDays(30));
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    deletionService.cancelAccountDeletion("testuser");

    assertNull(user.getDeletionScheduledAt());
    verify(userRepository).save(user);
  }
}
