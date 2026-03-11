package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.HeatmapResponse;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.AuditLogRepository;
import com.revature.passwordmanager.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessHeatmapServiceTest {

  @Mock
  private AuditLogRepository auditLogRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private AccessHeatmapService accessHeatmapService;

  private User user;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L).username("testuser")
        .masterPasswordHash("hash").salt("salt")
        .build();
  }

  @Test
  void getAccessHeatmap_ShouldReturnCorrectDistribution() {
    // 2026-02-09 is a Monday
    LocalDateTime monday9am = LocalDateTime.of(2026, 2, 9, 9, 0);
    LocalDateTime monday930am = LocalDateTime.of(2026, 2, 9, 9, 30);

    // 2026-02-10 is a Tuesday
    LocalDateTime tuesday2pm = LocalDateTime.of(2026, 2, 10, 14, 0);

    AuditLog log1 = AuditLog.builder().id(1L).user(user)
        .action(AuditLog.AuditAction.LOGIN)
        .timestamp(monday9am)
        .build();
    AuditLog log2 = AuditLog.builder().id(2L).user(user)
        .action(AuditLog.AuditAction.PASSWORD_VIEWED)
        .timestamp(monday930am)
        .build();
    AuditLog log3 = AuditLog.builder().id(3L).user(user)
        .action(AuditLog.AuditAction.LOGIN)
        .timestamp(tuesday2pm)
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    // Service now uses findByUserIdAndTimestampAfter
    when(auditLogRepository.findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class)))
        .thenReturn(List.of(log1, log2, log3));

    HeatmapResponse result = accessHeatmapService.getAccessHeatmap("testuser");

    assertNotNull(result);
    assertEquals(3, result.getTotalAccesses());
    assertEquals(9, result.getPeakHour());
    // Java DayOfWeek MONDAY is index 1. Our service maps Mon->1.
    // Wait, let's check service logic: dailyCounts[dayIndex] where dayIndex =
    // day.getValue() % 7.
    // Mon(1)%7 = 1. Tue(2)%7 = 2. Sun(7)%7 = 0.
    // So Array: Sun=0, Mon=1, Tue=2...
    // PeakDayName logic: if index=1, DayOfWeek.of(1) -> MONDAY.
    assertEquals("Monday", result.getPeakDay());

    // Validation of list values
    assertEquals(2, result.getAccessByHour().get(9)); // Two logins at 9am hour
    assertEquals(1, result.getAccessByHour().get(14)); // One login at 2pm hour

    assertEquals(2, result.getAccessByDay().get(1)); // Two on Monday (index 1)
    assertEquals(1, result.getAccessByDay().get(2)); // One on Tuesday (index 2)
  }

  @Test
  void getAccessHeatmap_EmptyLogs_ShouldReturnZeros() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(auditLogRepository.findByUserIdAndTimestampAfter(eq(1L), any(LocalDateTime.class)))
        .thenReturn(Collections.emptyList());

    HeatmapResponse result = accessHeatmapService.getAccessHeatmap("testuser");

    assertEquals(0, result.getTotalAccesses());
    assertEquals(-1, result.getPeakHour()); // Implementation returns -1 if no peak
  }
}
