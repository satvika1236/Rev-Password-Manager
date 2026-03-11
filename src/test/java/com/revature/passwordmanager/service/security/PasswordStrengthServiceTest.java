package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.response.PasswordStrengthResponse;
import com.revature.passwordmanager.util.PasswordStrengthCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordStrengthServiceTest {

  private PasswordStrengthService passwordStrengthService;

  @BeforeEach
  void setUp() {
    PasswordStrengthCalculator calculator = new PasswordStrengthCalculator();
    passwordStrengthService = new PasswordStrengthService(calculator);
  }

  @Test
  void analyzePassword_StrongPassword_ShouldReturnHighScore() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword("MyStr0ng!Pass#2024");

    assertNotNull(response);
    assertTrue(response.getScore() >= 60, "Strong password should score >= 60");
    assertNotNull(response.getLabel());
    assertNotNull(response.getFeedback());
  }

  @Test
  void analyzePassword_WeakPassword_ShouldReturnLowScoreWithFeedback() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword("abc");

    assertNotNull(response);
    assertTrue(response.getScore() < 60, "Weak password should score < 60");
    assertFalse(response.getFeedback().isEmpty(), "Weak password should have feedback");
    assertTrue(response.getFeedback().stream()
        .anyMatch(f -> f.contains("short")));
  }

  @Test
  void analyzePassword_Empty_ShouldReturnEmptyFeedback() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword("");

    assertNotNull(response);
    assertEquals(0, response.getScore());
    assertTrue(response.getFeedback().stream()
        .anyMatch(f -> f.contains("empty")));
  }

  @Test
  void analyzePassword_Null_ShouldReturnEmptyFeedback() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword(null);

    assertNotNull(response);
    assertEquals(0, response.getScore());
    assertTrue(response.getFeedback().stream()
        .anyMatch(f -> f.contains("empty")));
  }

  @Test
  void analyzePassword_MissingUppercase_ShouldSuggestUppercase() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword("lowercase123!");

    assertNotNull(response);
    assertTrue(response.getFeedback().stream()
        .anyMatch(f -> f.contains("uppercase")));
  }

  @Test
  void analyzePassword_NumbersOnly_ShouldHaveLowScore() {
    PasswordStrengthResponse response = passwordStrengthService.analyzePassword("12345678");

    assertNotNull(response);
    assertNotNull(response.getLabel());
    assertTrue(response.getFeedback().stream()
        .anyMatch(f -> f.contains("uppercase") || f.contains("lowercase") || f.contains("special")));
  }
}
