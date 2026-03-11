package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.NotificationDTO;
import com.revature.passwordmanager.dto.response.MessageResponse;
import com.revature.passwordmanager.service.notification.NotificationService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import com.revature.passwordmanager.dto.response.UnreadCountResponse;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

  private final NotificationService notificationService;

  @GetMapping
  public ResponseEntity<List<NotificationDTO>> getNotifications() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(notificationService.getNotifications(username));
  }

  @GetMapping("/unread-count")
  public ResponseEntity<UnreadCountResponse> getUnreadCount() {
    String username = getCurrentUsername();
    long count = notificationService.getUnreadCount(username);
    return ResponseEntity.ok(new UnreadCountResponse(count));
  }

  @PutMapping("/{id}/read")
  public ResponseEntity<MessageResponse> markAsRead(@PathVariable Long id) {
    String username = getCurrentUsername();
    notificationService.markAsRead(username, id);
    return ResponseEntity.ok(new MessageResponse("Notification marked as read"));
  }

  @PutMapping("/mark-all-read")
  public ResponseEntity<MessageResponse> markAllAsRead() {
    String username = getCurrentUsername();
    notificationService.markAllAsRead(username);
    return ResponseEntity.ok(new MessageResponse("All notifications marked as read"));
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<MessageResponse> deleteNotification(@PathVariable Long id) {
    String username = getCurrentUsername();
    notificationService.deleteNotification(username, id);
    return ResponseEntity.ok(new MessageResponse("Notification deleted"));
  }

  private String getCurrentUsername() {
    return SecurityContextHolder.getContext().getAuthentication().getName();
  }
}
