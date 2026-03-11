package com.revature.passwordmanager.service.notification;

import com.revature.passwordmanager.dto.NotificationDTO;
import com.revature.passwordmanager.model.notification.Notification;
import com.revature.passwordmanager.model.notification.Notification.NotificationType;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.NotificationRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.notification.NotificationService;

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
class NotificationServiceTest {

  @Mock
  private NotificationRepository notificationRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private NotificationService notificationService;

  private User user;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L).username("testuser")
        .masterPasswordHash("hash").salt("salt")
        .build();
  }

  @Test
  void createNotification_ShouldSave() {
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(notificationRepository.save(any(Notification.class))).thenAnswer(i -> i.getArgument(0));

    notificationService.createNotification("testuser",
        NotificationType.PASSWORD_EXPIRY, "Password Expiring", "Your password is about to expire");

    verify(notificationRepository).save(any(Notification.class));
  }

  @Test
  void getNotifications_ShouldReturnList() {
    Notification notification = Notification.builder()
        .id(1L).user(user).notificationType(NotificationType.SECURITY_ALERT)
        .title("Alert").message("Security alert").isRead(false)
        .createdAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(notificationRepository.findByUserIdOrderByCreatedAtDesc(1L))
        .thenReturn(List.of(notification));

    List<NotificationDTO> results = notificationService.getNotifications("testuser");

    assertEquals(1, results.size());
    assertEquals("SECURITY_ALERT", results.get(0).getNotificationType());
  }

  @Test
  void markAsRead_ShouldUpdateNotification() {
    Notification notification = Notification.builder()
        .id(1L).user(user).notificationType(NotificationType.BACKUP_REMINDER)
        .title("Backup").message("Time to backup").isRead(false)
        .createdAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(notificationRepository.findById(1L)).thenReturn(Optional.of(notification));

    notificationService.markAsRead("testuser", 1L);

    assertTrue(notification.isRead());
    verify(notificationRepository).save(notification);
  }

  @Test
  void getUnreadCount_ShouldReturnCount() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(notificationRepository.countByUserIdAndIsReadFalse(1L)).thenReturn(5L);

    long count = notificationService.getUnreadCount("testuser");

    assertEquals(5, count);
  }

  @Test
  void markAllAsRead_ShouldUpdateAllUnread() {
    Notification n1 = Notification.builder()
        .id(1L).user(user).notificationType(NotificationType.SECURITY_ALERT)
        .title("Alert 1").message("Message 1").isRead(false)
        .createdAt(LocalDateTime.now()).build();
    Notification n2 = Notification.builder()
        .id(2L).user(user).notificationType(NotificationType.PASSWORD_EXPIRY)
        .title("Alert 2").message("Message 2").isRead(false)
        .createdAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(notificationRepository.findByUserIdAndIsReadFalseOrderByCreatedAtDesc(1L))
        .thenReturn(List.of(n1, n2));

    notificationService.markAllAsRead("testuser");

    assertTrue(n1.isRead());
    assertTrue(n2.isRead());
    verify(notificationRepository).saveAll(List.of(n1, n2));
  }

  @Test
  void deleteNotification_ShouldDelete() {
    Notification notification = Notification.builder()
        .id(1L).user(user).notificationType(NotificationType.BACKUP_REMINDER)
        .title("Backup").message("Time to backup").isRead(false)
        .createdAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(notificationRepository.findById(1L)).thenReturn(Optional.of(notification));

    notificationService.deleteNotification("testuser", 1L);

    verify(notificationRepository).delete(notification);
  }
}
