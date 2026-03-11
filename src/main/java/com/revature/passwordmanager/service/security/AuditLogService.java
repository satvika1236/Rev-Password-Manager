package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.AuditLogResponse;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.AuditLogRepository;
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
public class AuditLogService {

  private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);

  private final AuditLogRepository auditLogRepository;
  private final UserRepository userRepository;

  @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
  public void logAction(String username, AuditAction action, String details) {
    logAction(username, action, details, null);
  }

  @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
  public void logAction(String username, AuditAction action, String details, String ipAddress) {
    try {
      User user = userRepository.findByUsername(username).orElse(null);
      if (user == null) {
        logger.warn("Cannot log audit action for unknown user: {}", username);
        return;
      }

      AuditLog log = AuditLog.builder()
          .user(user)
          .action(action)
          .details(details)
          .ipAddress(ipAddress)
          .timestamp(LocalDateTime.now())
          .build();

      auditLogRepository.save(log);
      logger.debug("Audit log: {} - {} - {}", username, action, details);
    } catch (Exception e) {

      logger.error("Failed to create audit log: {}", e.getMessage());
    }
  }

  @Transactional(readOnly = true)
  public List<AuditLogResponse> getAuditLogs(String username) {
    User user = userRepository.findByUsernameOrThrow(username);

    List<AuditLog> logs = auditLogRepository.findByUserIdOrderByTimestampDesc(user.getId());
    return logs.stream()
        .map(this::mapToResponse)
        .collect(Collectors.toList());
  }

  private AuditLogResponse mapToResponse(AuditLog log) {
    return AuditLogResponse.builder()
        .id(log.getId())
        .action(log.getAction().name())
        .details(log.getDetails())
        .ipAddress(log.getIpAddress())
        .timestamp(log.getTimestamp())
        .build();
  }
}
