package com.revature.passwordmanager.service.backup;

import com.revature.passwordmanager.dto.response.ExportResponse;
import com.revature.passwordmanager.model.backup.BackupExport;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.BackupExportRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.service.security.AuditLogService;
import com.revature.passwordmanager.service.security.EncryptionService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ExportServiceTest {

  @Mock
  private VaultEntryRepository vaultEntryRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private BackupExportRepository backupExportRepository;
  @Mock
  private EncryptionService encryptionService;
  @Mock
  private AuditLogService auditLogService;

  @InjectMocks
  private ExportService exportService;

  private User user;
  private VaultEntry sampleEntry;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L).username("testuser")
        .masterPasswordHash("hash").salt("salt")
        .build();
    sampleEntry = VaultEntry.builder()
        .id(1L).user(user).title("Google").username("user@gmail.com")
        .websiteUrl("https://google.com").notes("test")
        .build();
    lenient().when(encryptionService.decrypt(anyString(), any())).thenAnswer(i -> i.getArgument(0));
  }

  @Test
  void exportVault_Json_ShouldReturnJsonData() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));

    ExportResponse response = exportService.exportVault("testuser", "JSON");

    assertNotNull(response);
    assertEquals("JSON", response.getFormat());
    assertEquals(1, response.getEntryCount());
    assertFalse(response.isEncrypted());
    assertTrue(response.getData().contains("Google"));
    verify(backupExportRepository).save(any(BackupExport.class));
    verify(auditLogService).logAction(eq("testuser"), eq(AuditAction.VAULT_EXPORTED), anyString());
  }

  @Test
  void exportVault_Csv_ShouldReturnCsvData() {
    VaultEntry entry = VaultEntry.builder()
        .id(1L).user(user).title("Twitter").username("user")
        .websiteUrl("https://twitter.com").notes("")
        .build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(entry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));

    ExportResponse response = exportService.exportVault("testuser", "CSV");

    assertNotNull(response);
    assertEquals("CSV", response.getFormat());
    assertFalse(response.isEncrypted());
    assertTrue(response.getData().contains("title,username"));
    assertTrue(response.getData().contains("Twitter"));
    verify(auditLogService).logAction(eq("testuser"), eq(AuditAction.VAULT_EXPORTED), contains("CSV"));
  }

  @Test
  void exportVault_WithPassword_ShouldReturnEncryptedData() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));
    when(encryptionService.encryptForExport(anyString(), eq("myPassword"), anyString()))
        .thenReturn("encryptedPayload123");

    ExportResponse response = exportService.exportVault("testuser", "JSON", "myPassword");

    assertNotNull(response);
    assertTrue(response.isEncrypted());
    assertTrue(response.getData().contains("encryptedPayload123"));
    assertTrue(response.getData().contains(":"));
    assertEquals(1, response.getEntryCount());
    verify(encryptionService).encryptForExport(anyString(), eq("myPassword"), anyString());
    verify(auditLogService).logAction(eq("testuser"), eq(AuditAction.VAULT_EXPORTED), contains("true"));
  }

  @Test
  void exportVault_EncryptedAlias_ShouldReturnEncryptedData() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));
    when(encryptionService.encryptForExport(anyString(), eq("myPassword"), anyString()))
        .thenReturn("encryptedPayload123");

    ExportResponse response = exportService.exportVault("testuser", "ENCRYPTED", "myPassword");

    assertNotNull(response);
    assertEquals("ENCRYPTED", response.getFormat());
    assertTrue(response.isEncrypted());
    assertTrue(response.getData().contains("encryptedPayload123"));
  }

  @Test
  void exportVault_WithNullPassword_ShouldNotEncrypt() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));

    ExportResponse response = exportService.exportVault("testuser", "JSON", null);

    assertFalse(response.isEncrypted());
    assertTrue(response.getData().contains("Google"));
    verify(encryptionService, never()).encryptForExport(anyString(), anyString(), anyString());
  }

  @Test
  void exportVault_WithBlankPassword_ShouldNotEncrypt() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));

    ExportResponse response = exportService.exportVault("testuser", "JSON", "   ");

    assertFalse(response.isEncrypted());
    verify(encryptionService, never()).encryptForExport(anyString(), anyString(), anyString());
  }

  @Test
  void exportVault_EmptyVault_ShouldReturnZeroEntries() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(Collections.emptyList());
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> i.getArgument(0));

    ExportResponse response = exportService.exportVault("testuser", "JSON");

    assertNotNull(response);
    assertEquals(0, response.getEntryCount());
    assertFalse(response.isEncrypted());
    verify(auditLogService).logAction(eq("testuser"), eq(AuditAction.VAULT_EXPORTED), contains("0 entries"));
  }

  @Test
  void exportVault_ShouldSaveExportRecord() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));
    when(backupExportRepository.save(any(BackupExport.class))).thenAnswer(i -> {
      BackupExport saved = i.getArgument(0);
      assertEquals(user, saved.getUser());
      assertEquals(1, saved.getEntryCount());
      assertNotNull(saved.getCreatedAt());
      return saved;
    });

    exportService.exportVault("testuser", "JSON", "secret");

    verify(backupExportRepository).save(any(BackupExport.class));
  }

  @Test
  void previewExport_ShouldReturnPreviewData() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(sampleEntry));

    ExportResponse response = exportService.previewExport("testuser", "JSON");

    assertNotNull(response);
    assertEquals("JSON", response.getFormat());
    assertEquals(1, response.getEntryCount());
    assertFalse(response.isEncrypted());
    assertTrue(response.getData().contains("Google"));
    verify(backupExportRepository, never()).save(any(BackupExport.class));
    verify(auditLogService, never()).logAction(anyString(), any(AuditAction.class), anyString());
  }
}
