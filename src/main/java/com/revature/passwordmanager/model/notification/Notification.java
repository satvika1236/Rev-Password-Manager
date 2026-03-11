package com.revature.passwordmanager.model.notification;

import com.revature.passwordmanager.model.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "notifications")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Notification {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @Enumerated(EnumType.STRING)
  @Column(name = "notification_type", nullable = false, length = 50)
  private NotificationType notificationType;

  @Column(nullable = false, length = 200)
  private String title;

  @Column(nullable = false, length = 1000)
  private String message;

  @Column(name = "is_read")
  @Builder.Default
  private boolean isRead = false;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  public enum NotificationType {
    PASSWORD_EXPIRY,
    SECURITY_ALERT,
    BACKUP_REMINDER,
    SYSTEM_UPDATE,
    BREACH_DETECTED,
    ACCOUNT_ACTIVITY
  }
}
