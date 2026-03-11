package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.SecurityAlertDTO;
import com.revature.passwordmanager.model.security.SecurityAlert;
import com.revature.passwordmanager.model.security.SecurityAlert.AlertType;
import com.revature.passwordmanager.model.security.SecurityAlert.Severity;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.SecurityAlertRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.notification.NotificationService;
import com.revature.passwordmanager.model.notification.Notification.NotificationType;
import com.revature.passwordmanager.service.security.SecurityAlertService;

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
class SecurityAlertServiceTest {

  @Mock
  private SecurityAlertRepository securityAlertRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private NotificationService notificationService;

  @InjectMocks
  private SecurityAlertService securityAlertService;

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
  void createAlert_ShouldSaveAlert() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(securityAlertRepository.save(any(SecurityAlert.class))).thenAnswer(i -> i.getArgument(0));

    securityAlertService.createAlert("testuser", AlertType.NEW_DEVICE_LOGIN,
        "New Device Login", "Login from new device detected", Severity.HIGH);

    verify(securityAlertRepository).save(argThat(alert -> {
      assertEquals(user, alert.getUser());
      assertEquals(AlertType.NEW_DEVICE_LOGIN, alert.getAlertType());
      assertEquals("New Device Login", alert.getTitle());
      assertEquals(Severity.HIGH, alert.getSeverity());
      assertFalse(alert.isRead());
      return true;
    }));

    verify(notificationService).createNotification(
        eq("testuser"),
        eq(NotificationType.SECURITY_ALERT),
        eq("Security Alert: New Device Login"),
        eq("Login from new device detected"));
  }

  @Test
  void getAlerts_ShouldReturnList() {
    SecurityAlert alert = SecurityAlert.builder()
        .id(1L).user(user).alertType(AlertType.MULTIPLE_FAILED_LOGINS)
        .title("Failed Logins").message("Multiple failed login attempts detected")
        .severity(Severity.HIGH).isRead(false)
        .createdAt(LocalDateTime.of(2026, 2, 15, 10, 0))
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(securityAlertRepository.findByUserIdOrderByCreatedAtDesc(1L))
        .thenReturn(List.of(alert));

    List<SecurityAlertDTO> results = securityAlertService.getAlerts("testuser");

    assertNotNull(results);
    assertEquals(1, results.size());
    assertEquals("MULTIPLE_FAILED_LOGINS", results.get(0).getAlertType());
    assertEquals("Failed Logins", results.get(0).getTitle());
  }

  @Test
  void markAsRead_ShouldUpdateAlert() {
    SecurityAlert alert = SecurityAlert.builder()
        .id(1L).user(user).alertType(AlertType.PASSWORD_CHANGED)
        .title("Password Changed").message("Your password was changed")
        .severity(Severity.MEDIUM).isRead(false)
        .createdAt(LocalDateTime.now())
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(securityAlertRepository.findById(1L)).thenReturn(Optional.of(alert));

    securityAlertService.markAsRead("testuser", 1L);

    assertTrue(alert.isRead());
    verify(securityAlertRepository).save(alert);
  }

  @Test
  void deleteAlert_ShouldDeleteAlert() {
    SecurityAlert alert = SecurityAlert.builder()
        .id(1L).user(user).alertType(AlertType.TWO_FA_ENABLED)
        .title("2FA Enabled").message("Two-factor authentication enabled")
        .severity(Severity.LOW).isRead(true)
        .createdAt(LocalDateTime.now())
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(securityAlertRepository.findById(1L)).thenReturn(Optional.of(alert));

    securityAlertService.deleteAlert("testuser", 1L);

    verify(securityAlertRepository).delete(alert);
  }

  @Test
  void markAsRead_WrongUser_ShouldThrow() {
    User otherUser = User.builder().id(2L).username("otheruser").build();
    SecurityAlert alert = SecurityAlert.builder()
        .id(1L).user(otherUser).alertType(AlertType.ACCOUNT_LOCKED)
        .title("Locked").message("Account locked")
        .severity(Severity.CRITICAL).isRead(false)
        .createdAt(LocalDateTime.now())
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(securityAlertRepository.findById(1L)).thenReturn(Optional.of(alert));

    assertThrows(IllegalArgumentException.class,
        () -> securityAlertService.markAsRead("testuser", 1L));
  }
}
