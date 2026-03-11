package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.dto.request.PasswordGeneratorRequest;
import com.revature.passwordmanager.dto.response.PasswordStrengthResponse;
import com.revature.passwordmanager.service.security.PasswordGeneratorService;
import com.revature.passwordmanager.service.security.PasswordStrengthService;
import com.revature.passwordmanager.util.PasswordStrengthCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PasswordGeneratorServiceTest {

  private PasswordGeneratorService generatorService;
  private PasswordStrengthService strengthService;
  private PasswordStrengthCalculator calculator;

  @BeforeEach
  void setUp() {
    generatorService = new PasswordGeneratorService();
    calculator = new PasswordStrengthCalculator();
    strengthService = new PasswordStrengthService(calculator);
  }

  @Test
  void testGeneratePassword_DefaultSettings() {
    PasswordGeneratorRequest request = new PasswordGeneratorRequest();
    String password = generatorService.generatePassword(request);

    assertNotNull(password);
    assertEquals(16, password.length());
  }

  @Test
  void testGeneratePassword_CustomLength() {
    PasswordGeneratorRequest request = PasswordGeneratorRequest.builder()
        .length(20)
        .build();
    String password = generatorService.generatePassword(request);

    assertEquals(20, password.length());
  }

  @Test
  void testStrengthCalculation_Weak() {
    String weakPassword = "weak";
    PasswordStrengthResponse response = strengthService.analyzePassword(weakPassword);

    assertTrue(response.getScore() < 50);
    assertEquals("Very Weak", response.getLabel());
  }

  @Test
  void testStrengthCalculation_Strong() {
    String strongPassword = "CorrectHorseBatteryStaple1!";
    PasswordStrengthResponse response = strengthService.analyzePassword(strongPassword);

    assertTrue(response.getScore() > 70);
    assertTrue(response.getLabel().equals("Good") || response.getLabel().equals("Strong"));
  }
}
