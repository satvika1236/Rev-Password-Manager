package com.revature.passwordmanager.service.notification;

import com.revature.passwordmanager.dto.NotificationDTO;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.notification.Notification;
import com.revature.passwordmanager.model.notification.Notification.NotificationType;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.NotificationRepository;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class NotificationService {

  private static final Logger logger = LoggerFactory.getLogger(NotificationService.class);

  private final NotificationRepository notificationRepository;
  private final UserRepository userRepository;

  @Transactional
  public void createNotification(String username, NotificationType type,
      String title, String message) {
    User user = userRepository.findByUsername(username).orElse(null);
    if (user == null) {
      logger.warn("Cannot create notification for unknown user: {}", username);
      return;
    }

    Notification notification = Notification.builder()
        .user(user)
        .notificationType(type)
        .title(title)
        .message(message)
        .isRead(false)
        .createdAt(LocalDateTime.now())
        .build();
    notificationRepository.save(notification);
  }

  @Transactional(readOnly = true)
  public List<NotificationDTO> getNotifications(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    return notificationRepository.findByUserIdOrderByCreatedAtDesc(user.getId())
        .stream().map(this::mapToDTO).collect(Collectors.toList());
  }

  @Transactional(readOnly = true)
  public long getUnreadCount(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    long count = notificationRepository.countByUserIdAndIsReadFalse(user.getId());
    logger.debug("Unread notification count for user {}: {}", username, count);
    return count;
  }

  @Transactional
  public void markAsRead(String username, Long notificationId) {
    User user = userRepository.findByUsernameOrThrow(username);
    Notification notification = notificationRepository.findById(notificationId)
        .orElseThrow(() -> new ResourceNotFoundException("Notification not found"));
    if (!notification.getUser().getId().equals(user.getId())) {
      throw new IllegalArgumentException("Notification does not belong to user");
    }
    notification.setRead(true);
    notificationRepository.save(notification);
    logger.info("Marked notification {} as read for user {}", notificationId, username);
  }

  @Transactional
  public void markAllAsRead(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    List<Notification> unread = notificationRepository
        .findByUserIdAndIsReadFalseOrderByCreatedAtDesc(user.getId());
    logger.info("Marking {} notifications as read for user {}", unread.size(), username);
    unread.forEach(n -> n.setRead(true));
    notificationRepository.saveAll(unread);
    logger.info("Successfully marked all notifications as read for user {}", username);
  }

  @Transactional
  public void deleteNotification(String username, Long notificationId) {
    User user = userRepository.findByUsernameOrThrow(username);
    Notification notification = notificationRepository.findById(notificationId)
        .orElseThrow(() -> new ResourceNotFoundException("Notification not found"));
    if (!notification.getUser().getId().equals(user.getId())) {
      throw new IllegalArgumentException("Notification does not belong to user");
    }
    notificationRepository.delete(notification);
  }

  private NotificationDTO mapToDTO(Notification notification) {
    return NotificationDTO.builder()
        .id(notification.getId())
        .notificationType(notification.getNotificationType().name())
        .title(notification.getTitle())
        .message(notification.getMessage())
        .isRead(notification.isRead())
        .createdAt(notification.getCreatedAt())
        .build();
  }
}
