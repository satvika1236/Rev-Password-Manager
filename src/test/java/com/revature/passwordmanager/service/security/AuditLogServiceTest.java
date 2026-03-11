package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.AuditLogResponse;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.AuditLogRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.AuditLogService;

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
class AuditLogServiceTest {

  @Mock
  private AuditLogRepository auditLogRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private AuditLogService auditLogService;

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
  void logAction_ShouldSaveAuditLog() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(i -> i.getArgument(0));

    auditLogService.logAction("testuser", AuditAction.LOGIN, "Successful login");

    verify(auditLogRepository).save(argThat(log -> {
      assertEquals(user, log.getUser());
      assertEquals(AuditAction.LOGIN, log.getAction());
      assertEquals("Successful login", log.getDetails());
      assertNull(log.getIpAddress());
      assertNotNull(log.getTimestamp());
      return true;
    }));
  }

  @Test
  void logAction_WithIpAddress_ShouldSaveWithIp() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(i -> i.getArgument(0));

    auditLogService.logAction("testuser", AuditAction.LOGIN, "Login", "192.168.1.1");

    verify(auditLogRepository).save(argThat(log -> {
      assertEquals("192.168.1.1", log.getIpAddress());
      return true;
    }));
  }

  @Test
  void getAuditLogs_ShouldReturnUserLogs() {
    AuditLog log1 = AuditLog.builder()
        .id(1L).user(user).action(AuditAction.LOGIN)
        .details("Login").timestamp(LocalDateTime.of(2026, 1, 1, 10, 0))
        .build();
    AuditLog log2 = AuditLog.builder()
        .id(2L).user(user).action(AuditAction.ENTRY_CREATED)
        .details("Created entry: Test").timestamp(LocalDateTime.of(2026, 1, 2, 10, 0))
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(auditLogRepository.findByUserIdOrderByTimestampDesc(1L))
        .thenReturn(List.of(log2, log1));

    List<AuditLogResponse> results = auditLogService.getAuditLogs("testuser");

    assertNotNull(results);
    assertEquals(2, results.size());
    assertEquals("ENTRY_CREATED", results.get(0).getAction());
    assertEquals("LOGIN", results.get(1).getAction());
  }
}
