package com.revature.passwordmanager.service.backup;

import com.revature.passwordmanager.dto.request.ImportRequest;
import com.revature.passwordmanager.dto.response.ImportResult;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.service.vault.VaultService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ImportServiceTest {

  @Mock
  private VaultService vaultService;

  @Mock
  private UserRepository userRepository;

  @Mock
  private EncryptionService encryptionService;

  @Mock
  private VaultEntryRepository vaultEntryRepository;

  @Mock
  private CategoryRepository categoryRepository;

  @Mock
  private FolderRepository folderRepository;

  @InjectMocks
  private ImportService importService;

  private User testUser;
  private SecretKey testKey;

  @BeforeEach
  void setUp() throws Exception {
    testUser = new User();
    testUser.setId(1L);
    testUser.setUsername("testuser");
    testUser.setSalt("testsalt");
    testUser.setMasterPasswordHash("$2a$10$hashedPasswordValue");

    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    testKey = keyGenerator.generateKey();
  }

  @Test
  void importVault_Json_Success() {
    // Arrange
    String json = "[{\"title\":\"Test Entry\",\"username\":\"user\",\"password\":\"pass\",\"websiteUrl\":\"http://example.com\",\"notes\":\"note\"}]";
    ImportRequest request = new ImportRequest();
    request.setFormat("JSON");
    request.setData(json);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);
    when(encryptionService.encrypt(anyString(), any())).thenReturn("encrypted_value");

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(1, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    verify(vaultService, times(1)).bulkInsert(anyString(), anyList());
  }

  @Test
  void importVault_Csv_Success() {
    // Arrange
    String csv = "Title,Username,Password,Url,Notes\nTest Entry,user,pass,http://example.com,note";
    ImportRequest request = new ImportRequest();
    request.setFormat("CSV");
    request.setData(csv);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);
    when(encryptionService.encrypt(anyString(), any())).thenReturn("encrypted_value");

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(1, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    verify(vaultService, times(1)).bulkInsert(anyString(), anyList());
  }

  @Test
  void importVault_Json_InvalidFormat() {
    // Arrange
    String json = "{invalid_json}";
    ImportRequest request = new ImportRequest();
    request.setFormat("JSON");
    request.setData(json);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertEquals(1, result.getFailCount());
    assertEquals("Invalid JSON format", result.getMessage());
  }

  @Test
  void importVault_Csv_EmptyData() {
    // Arrange - empty string triggers the "Data is required" guard before CSV
    // parsing
    ImportRequest request = new ImportRequest();
    request.setFormat("CSV");
    request.setData("");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    assertEquals("Data is required", result.getMessage());
  }

  @Test
  void importVault_Csv_Empty() {
    // Arrange - a space string passes the isEmpty() guard but after trim() becomes
    // empty string. readLine() returns null → "Empty CSV"
    ImportRequest request = new ImportRequest();
    request.setFormat("CSV");
    request.setData(" "); // one space: not isEmpty(), but after trim() is empty, readLine() returns null

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    // After trim(), data is empty → readLine() returns null → "Empty CSV"
    assertEquals("Empty CSV", result.getMessage());
  }

  @Test
  void importVault_UnsupportedFormat() {
    // Arrange
    ImportRequest request = new ImportRequest();
    request.setFormat("XML");
    request.setData("<xml></xml>");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    // Act
    ImportResult result = importService.importVault("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertTrue(result.getMessage().contains("Unsupported format"));
  }

  @Test
  void validateImport_Json_Success() {
    String json = "[{\"title\":\"Test Entry\",\"username\":\"user\"}]";
    ImportRequest request = new ImportRequest();
    request.setFormat("JSON");
    request.setData(json);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    ImportResult result = importService.validateImport("testuser", request);

    assertEquals(1, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    assertEquals("Validation passed", result.getMessage());
    verify(vaultService, never()).bulkInsert(anyString(), anyList());
  }

  @Test
  void validateImport_Csv_Success() {
    String csv = "Title,Username\nTest Entry,user";
    ImportRequest request = new ImportRequest();
    request.setFormat("CSV");
    request.setData(csv);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    ImportResult result = importService.validateImport("testuser", request);

    assertEquals(1, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    assertEquals("Validation passed", result.getMessage());
    verify(vaultService, never()).bulkInsert(anyString(), anyList());
  }
}
