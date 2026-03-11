package com.revature.passwordmanager.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class MasterPasswordValidatorTest {

  @InjectMocks
  private MasterPasswordValidator validator;

  @Test
  void testValidate_WeakPassword_ReturnsFalse() {
    // Too short
    assertFalse(validator.isValid("short"));
    // No number
    assertFalse(validator.isValid("NoNumberPassword!"));
    // No special char
    assertFalse(validator.isValid("NoSpecialChar123"));
  }

  @Test
  void testValidate_StrongPassword_ReturnsTrue() {
    assertTrue(validator.isValid("StrongP@ssw0rd!"));
  }
}
