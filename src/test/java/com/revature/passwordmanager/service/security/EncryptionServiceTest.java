package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.config.EncryptionConfig;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.util.EncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class EncryptionServiceTest {

  @Mock
  private EncryptionConfig encryptionConfig;

  private EncryptionUtil encryptionUtil;

  private EncryptionService encryptionService;

  @BeforeEach
  void setUp() {
    // Setup EncryptionUtil with a real configuration for meaningful tests
    encryptionConfig = new EncryptionConfig();
    encryptionConfig.setAlgorithm("AES/GCM/NoPadding");
    encryptionConfig.setKeySize(256);

    encryptionUtil = new EncryptionUtil(encryptionConfig);
    encryptionService = new EncryptionService(encryptionUtil);
  }

  @Test
  void testEncryptionDecryptionFlow() throws Exception {
    SecretKey key = encryptionService.generateNewKey();
    String originalData = "SuperSecretData123!";

    String encryptedData = encryptionService.encrypt(originalData, key);
    assertNotNull(encryptedData);
    assertNotEquals(originalData, encryptedData);

    String decryptedData = encryptionService.decrypt(encryptedData, key);
    assertEquals(originalData, decryptedData);
  }

  @Test
  void testKeyStringConversion() throws Exception {
    SecretKey originalKey = encryptionService.generateNewKey();
    String keyString = encryptionService.encodeKey(originalKey);

    assertNotNull(keyString);

    SecretKey restoredKey = encryptionService.decodeKey(keyString);
    assertEquals(originalKey, restoredKey);
  }

  @Test
  void testDecryptWithWrongKeyFails() throws Exception {
    SecretKey key1 = encryptionService.generateNewKey();
    SecretKey key2 = encryptionService.generateNewKey();
    String originalData = "Secret";

    String encryptedData = encryptionService.encrypt(originalData, key1);

    assertThrows(Exception.class, () -> encryptionService.decrypt(encryptedData, key2));
  }

  @Test
  void testGenerateNewKey_ShouldReturnValidKey() {
    SecretKey key = encryptionService.generateNewKey();

    assertNotNull(key);
    assertEquals("AES", key.getAlgorithm());
    assertNotNull(key.getEncoded());
  }

  @Test
  void testEncryptForExport_ShouldEncryptData() {
    String data = "Sensitive vault data";
    String password = "exportPassword123!";
    String salt = "randomSalt";

    String encrypted = encryptionService.encryptForExport(data, password, salt);

    assertNotNull(encrypted);
    assertNotEquals(data, encrypted);
  }

  @Test
  void testDecryptForImport_ShouldDecryptData() {
    String originalData = "Sensitive vault data";
    String password = "exportPassword123!";
    String salt = "randomSalt";

    String encrypted = encryptionService.encryptForExport(originalData, password, salt);
    String decrypted = encryptionService.decryptForImport(encrypted, password, salt);

    assertEquals(originalData, decrypted);
  }
}
