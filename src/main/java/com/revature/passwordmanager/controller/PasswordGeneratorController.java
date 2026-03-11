package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.request.PasswordGeneratorRequest;
import com.revature.passwordmanager.dto.response.PasswordStrengthResponse;
import com.revature.passwordmanager.service.security.PasswordGeneratorService;
import com.revature.passwordmanager.service.security.PasswordStrengthService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import jakarta.validation.Valid;

import com.revature.passwordmanager.dto.response.GeneratedPasswordResponse;
import com.revature.passwordmanager.dto.request.PasswordStrengthCheckRequest;
import com.revature.passwordmanager.dto.response.GeneratedMultiplePasswordsResponse;
import com.revature.passwordmanager.dto.request.PasswordValidationRequest;

@RestController
@RequestMapping("/api/generator")
@RequiredArgsConstructor
public class PasswordGeneratorController {

  private final PasswordGeneratorService generatorService;
  private final PasswordStrengthService strengthService;

  @PostMapping("/generate")
  public ResponseEntity<GeneratedPasswordResponse> generatePassword(@RequestBody PasswordGeneratorRequest request) {
    String password = generatorService.generatePassword(request);
    return ResponseEntity.ok(new GeneratedPasswordResponse(password));
  }

  @PostMapping("/strength")
  public ResponseEntity<PasswordStrengthResponse> checkStrength(
      @Valid @RequestBody PasswordStrengthCheckRequest request) {
    String password = request.getPassword();
    PasswordStrengthResponse response = strengthService.analyzePassword(password);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/generate-multiple")
  public ResponseEntity<GeneratedMultiplePasswordsResponse> generateMultiple(
      @RequestBody PasswordGeneratorRequest request) {
    return ResponseEntity
        .ok(new GeneratedMultiplePasswordsResponse(generatorService.generateMultiplePasswords(request)));
  }

  @PostMapping("/validate")
  public ResponseEntity<PasswordStrengthResponse> validatePassword(
      @Valid @RequestBody PasswordValidationRequest request) {
    PasswordStrengthResponse response = strengthService.analyzePassword(request.getPassword());
    return ResponseEntity.ok(response);
  }

  @GetMapping("/default-settings")
  public ResponseEntity<PasswordGeneratorRequest> getDefaultSettings() {
    return ResponseEntity.ok(generatorService.getDefaultSettings());
  }
}
