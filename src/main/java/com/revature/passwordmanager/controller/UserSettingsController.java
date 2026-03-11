package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.request.UserSettingsRequest;
import com.revature.passwordmanager.dto.response.UserSettingsResponse;
import com.revature.passwordmanager.service.user.UserSettingsService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/settings")
@RequiredArgsConstructor
public class UserSettingsController {

  private final UserSettingsService userSettingsService;

  @GetMapping
  public ResponseEntity<UserSettingsResponse> getSettings() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(userSettingsService.getSettings(username));
  }

  @PutMapping
  public ResponseEntity<UserSettingsResponse> updateSettings(@RequestBody UserSettingsRequest request) {
    String username = getCurrentUsername();
    return ResponseEntity.ok(userSettingsService.updateSettings(username, request));
  }

  private String getCurrentUsername() {
    return SecurityContextHolder.getContext().getAuthentication().getName();
  }
}
