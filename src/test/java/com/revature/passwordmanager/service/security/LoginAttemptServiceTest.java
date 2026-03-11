package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.LoginHistoryResponse;
import com.revature.passwordmanager.model.security.LoginAttempt;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.LoginAttemptRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.LoginAttemptService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

  @Mock
  private LoginAttemptRepository loginAttemptRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private LoginAttemptService loginAttemptService;

  private User user;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .username("testuser")
        .email("test@example.com")
        .masterPasswordHash("hash")
        .salt("salt")
        .build();
  }

  @Test
  void recordLoginAttempt_Success_ShouldSave() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(i -> i.getArgument(0));

    loginAttemptService.recordLoginAttempt("testuser", true, null, "127.0.0.1", "Chrome", "Local", 0);

    verify(loginAttemptRepository).save(argThat(attempt -> {
      assertEquals(user, attempt.getUser());
      assertEquals("testuser", attempt.getUsernameAttempted());
      assertTrue(attempt.isSuccessful());
      assertNull(attempt.getFailureReason());
      assertEquals("127.0.0.1", attempt.getIpAddress());
      assertEquals("Chrome", attempt.getDeviceInfo());
      assertNotNull(attempt.getTimestamp());
      return true;
    }));
  }

  @Test
  void recordLoginAttempt_Failed_ShouldSave() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(i -> i.getArgument(0));

    loginAttemptService.recordLoginAttempt("testuser", false, "Invalid credentials", "192.168.1.1", null, "Unknown",
        50);

    verify(loginAttemptRepository).save(argThat(attempt -> {
      assertFalse(attempt.isSuccessful());
      assertEquals("Invalid credentials", attempt.getFailureReason());
      return true;
    }));
  }

  @Test
  void recordLoginAttempt_UnknownUser_ShouldSaveWithNullUser() {
    when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());
    when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(i -> i.getArgument(0));

    loginAttemptService.recordLoginAttempt("unknown", false, "User not found", null, null, null, 100);

    verify(loginAttemptRepository).save(argThat(attempt -> {
      assertNull(attempt.getUser());
      assertEquals("unknown", attempt.getUsernameAttempted());
      return true;
    }));
  }

  @Test
  void getLoginHistory_ShouldReturnMappedList() {
    LoginAttempt attempt1 = LoginAttempt.builder()
        .id(1L).user(user).usernameAttempted("testuser")
        .ipAddress("127.0.0.1").deviceInfo("Chrome")
        .successful(true).timestamp(LocalDateTime.of(2026, 2, 15, 10, 0))
        .build();
    LoginAttempt attempt2 = LoginAttempt.builder()
        .id(2L).user(user).usernameAttempted("testuser")
        .ipAddress("192.168.1.1").successful(false)
        .failureReason("Invalid credentials")
        .timestamp(LocalDateTime.of(2026, 2, 15, 9, 0))
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(loginAttemptRepository.findByUserIdOrderByTimestampDesc(1L))
        .thenReturn(List.of(attempt1, attempt2));

    List<LoginHistoryResponse> results = loginAttemptService.getLoginHistory("testuser");

    assertNotNull(results);
    assertEquals(2, results.size());
    assertTrue(results.get(0).isSuccessful());
    assertFalse(results.get(1).isSuccessful());
    assertEquals("Invalid credentials", results.get(1).getFailureReason());
  }

  @Test
  void getRecentFailedAttempts_ShouldReturnCount() {
    when(loginAttemptRepository.countByUsernameAttemptedAndSuccessfulFalseAndTimestampAfter(
        eq("testuser"), any(LocalDateTime.class))).thenReturn(3L);

    long count = loginAttemptService.getRecentFailedAttempts("testuser", 15);

    assertEquals(3L, count);
  }
}
