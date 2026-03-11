package com.revature.passwordmanager.scheduler;

import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Component
@RequiredArgsConstructor
public class AccountDeletionScheduler {

  private static final Logger logger = LoggerFactory.getLogger(AccountDeletionScheduler.class);
  private final UserRepository userRepository;

  @Scheduled(cron = "0 0 0 * * ?")
  @Transactional
  public void deleteExpiredAccounts() {
    logger.info("Running scheduled account deletion task...");

    List<User> expiredUsers = userRepository.findByDeletionScheduledAtBefore(LocalDateTime.now());

    for (User user : expiredUsers) {
      logger.info("Permanently deleting user: {}", user.getUsername());
      userRepository.delete(user);
    }

    if (!expiredUsers.isEmpty()) {
      logger.info("Deleted {} expired accounts.", expiredUsers.size());
    }
  }
}
