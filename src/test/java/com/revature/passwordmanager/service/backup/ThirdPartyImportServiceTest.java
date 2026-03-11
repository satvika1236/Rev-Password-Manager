package com.revature.passwordmanager.service.backup;

import com.revature.passwordmanager.dto.request.ThirdPartyImportRequest;
import com.revature.passwordmanager.dto.response.ImportResult;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.service.vault.VaultService;
import com.revature.passwordmanager.service.backup.importers.Importer;
import com.revature.passwordmanager.service.backup.importers.ImporterFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ThirdPartyImportServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private EncryptionService encryptionService;

  @Mock
  private VaultService vaultService;

  @Mock
  private ImporterFactory importerFactory;

  @Mock
  private Importer mockImporter;

  @InjectMocks
  private ThirdPartyImportService thirdPartyImportService;

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
  void importFromThirdParty_Success() throws Exception {
    // Arrange
    ThirdPartyImportRequest request = new ThirdPartyImportRequest();
    request.setSource("CHROME");
    request.setData("csv_data");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    when(importerFactory.getImporter("CHROME")).thenReturn(mockImporter);

    List<VaultEntry> parsedEntries = new ArrayList<>();
    parsedEntries.add(VaultEntry.builder().title("Test").build());
    when(mockImporter.parse(eq("csv_data"), eq(testUser), any(), eq(encryptionService)))
        .thenReturn(parsedEntries);

    // Act
    ImportResult result = thirdPartyImportService.importFromThirdParty("testuser", request);

    // Assert
    assertEquals(1, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    verify(vaultService, times(1)).bulkInsert("testuser", parsedEntries);
  }

  @Test
  void importFromThirdParty_UnsupportedSource() {
    // Arrange
    ThirdPartyImportRequest request = new ThirdPartyImportRequest();
    request.setSource("UNKNOWN");
    request.setData("csv_data");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    when(importerFactory.getImporter("UNKNOWN")).thenThrow(new IllegalArgumentException("Unsupported import source"));

    // Act
    ImportResult result = thirdPartyImportService.importFromThirdParty("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertEquals(0, result.getFailCount());
    assertTrue(result.getMessage().contains("Unsupported import source"));
    verify(vaultService, never()).bulkInsert(anyString(), anyList());
  }

  @Test
  void importFromThirdParty_ParsingError() throws Exception {
    // Arrange
    ThirdPartyImportRequest request = new ThirdPartyImportRequest();
    request.setSource("LASTPASS");
    request.setData("csv_data");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
    when(encryptionService.deriveKey(any(), any())).thenReturn(testKey);

    when(importerFactory.getImporter("LASTPASS")).thenReturn(mockImporter);
    when(mockImporter.parse(anyString(), any(), any(), any())).thenThrow(new RuntimeException("Parsing error"));

    // Act
    ImportResult result = thirdPartyImportService.importFromThirdParty("testuser", request);

    // Assert
    assertEquals(0, result.getSuccessCount());
    assertEquals(1, result.getFailCount());
    assertTrue(result.getMessage().contains("parsing error"));
    verify(vaultService, never()).bulkInsert(anyString(), anyList());
  }

  @Test
  void getSupportedFormats_ShouldReturnFormats() {
    when(importerFactory.getSupportedFormats()).thenReturn(List.of("CHROME", "LASTPASS"));

    List<String> formats = thirdPartyImportService.getSupportedFormats();

    assertEquals(2, formats.size());
    assertTrue(formats.contains("CHROME"));
    assertTrue(formats.contains("LASTPASS"));
  }
}
