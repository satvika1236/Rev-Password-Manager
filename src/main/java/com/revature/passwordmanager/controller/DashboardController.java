package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.response.PasswordAgeResponse;
import com.revature.passwordmanager.dto.response.PasswordHealthMetricsResponse;
import com.revature.passwordmanager.dto.response.ReusedPasswordResponse;
import com.revature.passwordmanager.dto.response.SecurityScoreResponse;
import com.revature.passwordmanager.dto.response.SecurityTrendResponse;
import com.revature.passwordmanager.service.dashboard.PasswordStrengthDashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@Tag(name = "Dashboard", description = "Password Strength Dashboard - security metrics and analytics")
public class DashboardController {

    private final PasswordStrengthDashboardService dashboardService;

    @Operation(summary = "Get overall security score (0-100) with a summary of vault health")
    @GetMapping("/security-score")
    public ResponseEntity<SecurityScoreResponse> getSecurityScore() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getSecurityScore(username));
    }

    @Operation(summary = "Get password health breakdown by strength category")
    @GetMapping("/password-health")
    public ResponseEntity<PasswordHealthMetricsResponse> getPasswordHealth() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getPasswordHealth(username));
    }

    @Operation(summary = "Get all groups of reused passwords across vault entries")
    @GetMapping("/reused-passwords")
    public ResponseEntity<ReusedPasswordResponse> getReusedPasswords() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getReusedPasswords(username));
    }

    @Operation(summary = "Get password age distribution across the vault")
    @GetMapping("/password-age")
    public ResponseEntity<PasswordAgeResponse> getPasswordAge() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getPasswordAge(username));
    }

    @Operation(summary = "Get historical security score trends (default last 30 days)")
    @GetMapping("/trends")
    public ResponseEntity<SecurityTrendResponse> getSecurityTrends(
            @RequestParam(defaultValue = "30") int days) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getSecurityTrends(username, days));
    }

    @Operation(summary = "Get list of all weak passwords")
    @GetMapping("/passwords/weak")
    public ResponseEntity<java.util.List<com.revature.passwordmanager.dto.response.VaultEntryResponse>> getWeakPasswordsList() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getWeakPasswordsList(username));
    }

    @Operation(summary = "Get list of all old passwords (>90 days)")
    @GetMapping("/passwords/old")
    public ResponseEntity<java.util.List<com.revature.passwordmanager.dto.response.VaultEntryResponse>> getOldPasswordsList() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(dashboardService.getOldPasswordsList(username));
    }

    private String getCurrentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
