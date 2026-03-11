package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.notification.Notification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.revature.passwordmanager.model.user.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface NotificationRepository extends JpaRepository<Notification, Long> {
  List<Notification> findByUserIdOrderByCreatedAtDesc(Long userId);

  List<Notification> findByUserIdAndIsReadFalseOrderByCreatedAtDesc(Long userId);

  long countByUserIdAndIsReadFalse(Long userId);

  List<Notification> findByUserOrderByCreatedAtDesc(User user);

  long countByUserAndIsReadFalse(User user);

  Optional<Notification> findByIdAndUser(Long id, User user);
}
