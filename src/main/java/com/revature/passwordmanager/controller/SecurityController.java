package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.SecurityAlertDTO;
import com.revature.passwordmanager.dto.response.AuditLogResponse;
import com.revature.passwordmanager.dto.response.LoginHistoryResponse;
import com.revature.passwordmanager.dto.response.MessageResponse;
import com.revature.passwordmanager.dto.response.SecurityAuditResponse;
import com.revature.passwordmanager.service.security.AuditLogService;
import com.revature.passwordmanager.service.security.LoginAttemptService;
import com.revature.passwordmanager.service.security.SecurityAlertService;
import com.revature.passwordmanager.service.security.SecurityAuditService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
public class SecurityController {

  private final AuditLogService auditLogService;
  private final LoginAttemptService loginAttemptService;
  private final SecurityAlertService securityAlertService;
  private final SecurityAuditService securityAuditService;

  @GetMapping("/audit-logs")
  public ResponseEntity<List<AuditLogResponse>> getAuditLogs() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(auditLogService.getAuditLogs(username));
  }

  @GetMapping("/login-history")
  public ResponseEntity<List<LoginHistoryResponse>> getLoginHistory() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(loginAttemptService.getLoginHistory(username));
  }

  @GetMapping("/alerts")
  public ResponseEntity<List<SecurityAlertDTO>> getAlerts() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(securityAlertService.getAlerts(username));
  }

  @PutMapping("/alerts/{id}/read")
  public ResponseEntity<MessageResponse> markAlertAsRead(@PathVariable Long id) {
    String username = getCurrentUsername();
    securityAlertService.markAsRead(username, id);
    return ResponseEntity.ok(new MessageResponse("Alert marked as read"));
  }

  @DeleteMapping("/alerts/{id}")
  public ResponseEntity<MessageResponse> deleteAlert(@PathVariable Long id) {
    String username = getCurrentUsername();
    securityAlertService.deleteAlert(username, id);
    return ResponseEntity.ok(new MessageResponse("Alert deleted"));
  }

  @GetMapping("/audit-report")
  public ResponseEntity<SecurityAuditResponse> getAuditReport() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(securityAuditService.generateAuditReport(username));
  }

  @GetMapping("/weak-passwords")
  public ResponseEntity<List<SecurityAuditResponse.VaultEntrySummary>> getWeakPasswords() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(securityAuditService.getWeakPasswords(username));
  }

  @GetMapping("/reused-passwords")
  public ResponseEntity<List<SecurityAuditResponse.VaultEntrySummary>> getReusedPasswords() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(securityAuditService.getReusedPasswords(username));
  }

  @GetMapping("/old-passwords")
  public ResponseEntity<List<SecurityAuditResponse.VaultEntrySummary>> getOldPasswords() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(securityAuditService.getOldPasswords(username));
  }

  @PostMapping("/analyze-vault")
  public ResponseEntity<SecurityAuditResponse> analyzeVault() {
    String username = getCurrentUsername();

    return ResponseEntity.ok(securityAuditService.generateAuditReport(username));
  }

  private String getCurrentUsername() {
    return SecurityContextHolder.getContext().getAuthentication().getName();
  }
}
