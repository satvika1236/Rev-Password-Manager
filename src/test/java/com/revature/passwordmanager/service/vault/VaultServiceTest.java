package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.request.VaultEntryRequest;
import com.revature.passwordmanager.dto.response.VaultEntryDetailResponse;
import com.revature.passwordmanager.dto.response.VaultEntryResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Category;
import com.revature.passwordmanager.model.vault.Folder;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.UserSettingsRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.service.vault.VaultService;
import com.revature.passwordmanager.service.vault.VaultSnapshotService;
import com.revature.passwordmanager.util.EncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import com.revature.passwordmanager.model.user.UserSettings;
import com.revature.passwordmanager.dto.request.SensitiveAccessRequest;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.service.auth.TwoFactorService;
import com.revature.passwordmanager.service.security.AuditLogService;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

  @Mock
  private VaultEntryRepository vaultEntryRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private CategoryRepository categoryRepository;
  @Mock
  private FolderRepository folderRepository;
  @Mock
  private EncryptionService encryptionService;
  @Mock
  private TwoFactorService twoFactorService; // Mock 2FA service
  @Mock
  private EncryptionUtil encryptionUtil;
  @Mock
  private VaultSnapshotService vaultSnapshotService;
  @Mock
  private AuditLogService auditLogService;
  @Mock
  private UserSettingsRepository userSettingsRepository;
  @Mock
  private com.revature.passwordmanager.util.PasswordStrengthCalculator passwordStrengthCalculator;
  @Mock
  private com.revature.passwordmanager.service.security.SecurityAuditService securityAuditService;
  @Mock
  private com.revature.passwordmanager.service.security.DuressService duressService;
  @Mock
  private com.revature.passwordmanager.security.JwtTokenProvider jwtTokenProvider;
  @Mock
  private org.springframework.security.authentication.AuthenticationManager authenticationManager;
  @Mock
  private com.revature.passwordmanager.service.notification.NotificationService notificationService;
  @Mock
  private com.revature.passwordmanager.repository.SecureShareRepository secureShareRepository;

  @InjectMocks
  private VaultService vaultService;

  // ... existing fields ...

  // ... existing methods ...

  @Test
  void getEntry_ShouldIncludeStrength_WhenPasswordAvailable() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.decrypt(anyString(), any())).thenReturn("password123");
    when(passwordStrengthCalculator.calculateScore("password123")).thenReturn(80);
    when(passwordStrengthCalculator.getStrengthLabel(80)).thenReturn("Strong");

    VaultEntryDetailResponse response = vaultService.getEntry("testuser", 1L);

    assertNotNull(response);
    assertEquals(80, response.getStrengthScore());
    assertEquals("Strong", response.getStrengthLabel());
  }

  private User user;
  private Category category;
  private Folder folder;
  private VaultEntry entry;
  private SecretKey mockKey;

  @BeforeEach
  void setUp() {
    org.springframework.security.core.context.SecurityContextHolder.clearContext();

    user = User.builder()
        .id(1L)
        .username("testuser")
        .masterPasswordHash("hash")
        .salt("salt")
        .build();

    category = Category.builder().id(1L).name("Login").build();
    folder = Folder.builder().id(1L).name("Work").build();

    mockKey = mock(SecretKey.class);

    entry = VaultEntry.builder()
        .id(1L)
        .user(user)
        .category(category)
        .folder(folder)
        .title("Test Entry")
        .username("encryptedUsername")
        .password("encryptedPassword")
        .isHighlySensitive(false)
        .build();
  }

  @Test
  void getEntry_ShouldReturnMaskedData_WhenHighlySensitive() {
    entry.setIsHighlySensitive(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    // decrypt is not called for masked fields

    VaultEntryDetailResponse response = vaultService.getEntry("testuser", 1L);

    assertNotNull(response);
    assertEquals("******", response.getPassword());
    assertEquals("******", response.getUsername());
    assertTrue(response.getRequiresSensitiveAuth());
  }

  @Test
  void accessSensitiveEntry_ShouldReturnDecrypted_WhenCredentialsValid() {
    entry.setIsHighlySensitive(true);
    SensitiveAccessRequest request = new SensitiveAccessRequest();
    request.setMasterPassword("password");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(encryptionUtil.deriveKey(eq("hash"), eq("salt"))).thenReturn(mockKey);
    when(encryptionService.decrypt(anyString(), any())).thenReturn("decrypted");
    // Mock the authentication check
    when(authenticationManager.authenticate(any())).thenReturn(null);

    VaultEntryDetailResponse response = vaultService.accessSensitiveEntry("testuser", 1L, request);

    assertNotNull(response);
    assertEquals("decrypted", response.getPassword());
    assertEquals("decrypted", response.getUsername());
  }

  @Test
  void accessSensitiveEntry_ShouldThrowException_WhenPasswordInvalid() {
    entry.setIsHighlySensitive(true);
    SensitiveAccessRequest request = new SensitiveAccessRequest();
    request.setMasterPassword("wrongpassword");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));

    // Mock the authentication check to throw an exception for invalid password
    when(authenticationManager.authenticate(any()))
        .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Invalid master password"));

    assertThrows(AuthenticationException.class,
        () -> vaultService.accessSensitiveEntry("testuser", 1L, request));
  }

  @Test
  void createEntry_ShouldReturnResponse_WhenValidRequest() {
    VaultEntryRequest request = new VaultEntryRequest();
    request.setTitle("Test Entry");
    request.setCategoryId(1L);
    request.setFolderId(1L);
    request.setPassword("password");
    request.setUsername("user");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(categoryRepository.findById(1L)).thenReturn(Optional.of(category));
    when(folderRepository.findById(1L)).thenReturn(Optional.of(folder));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.encrypt(anyString(), any())).thenReturn("encrypted");
    when(vaultEntryRepository.save(any(VaultEntry.class))).thenReturn(entry);

    VaultEntryResponse response = vaultService.createEntry("testuser", request);

    assertNotNull(response);
    assertEquals("Test Entry", response.getTitle());
    verify(vaultEntryRepository).save(any(VaultEntry.class));
  }

  @Test
  void getEntry_ShouldReturnDetailResponse_WhenFound() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.decrypt(anyString(), any())).thenReturn("decrypted");

    VaultEntryDetailResponse response = vaultService.getEntry("testuser", 1L);

    assertNotNull(response);
    assertEquals("decrypted", response.getPassword());
    assertEquals("decrypted", response.getUsername());
  }

  @Test
  void toggleFavorite_ShouldToggleStatus_WhenEntryExists() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(vaultEntryRepository.save(any(VaultEntry.class))).thenAnswer(invocation -> invocation.getArgument(0));

    // Initial state is false (default)
    VaultEntryResponse response = vaultService.toggleFavorite("testuser", 1L);

    assertNotNull(response);
    assertTrue(response.getIsFavorite());
    verify(vaultEntryRepository).save(any(VaultEntry.class));
  }

  @Test
  void searchEntries_ShouldReturnMatchingEntries_WhenKeywordProvided() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.searchEntries(eq(1L), eq("test"), any(), any(), any(), any()))
        .thenReturn(List.of(entry));

    List<VaultEntryResponse> results = vaultService.searchEntries(
        "testuser", "test", null, null, null, null, "title", "asc");

    assertNotNull(results);
    assertEquals(1, results.size());
    assertEquals("Test Entry", results.get(0).getTitle());
    verify(vaultEntryRepository).searchEntries(eq(1L), eq("test"), any(), any(), any(), any());
  }

  @Test
  void searchEntries_ShouldReturnFilteredEntries_WhenCategoryProvided() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.searchEntries(eq(1L), any(), eq(1L), any(), any(), any()))
        .thenReturn(List.of(entry));

    List<VaultEntryResponse> results = vaultService.searchEntries(
        "testuser", null, 1L, null, null, null, "title", "asc");

    assertNotNull(results);
    assertEquals(1, results.size());
    verify(vaultEntryRepository).searchEntries(eq(1L), any(), eq(1L), any(), any(), any());
  }

  @Test
  void searchEntries_ShouldReturnSortedEntries_WhenSortByProvided() {
    VaultEntry entry2 = VaultEntry.builder()
        .id(2L).user(user).category(category).folder(folder)
        .title("Zebra Entry").username("enc").password("enc")
        .createdAt(java.time.LocalDateTime.of(2025, 1, 1, 0, 0))
        .isHighlySensitive(false).build();
    entry.setCreatedAt(java.time.LocalDateTime.of(2026, 1, 1, 0, 0));

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.searchEntries(any(), any(), any(), any(), any(), any()))
        .thenReturn(List.of(entry2, entry));

    List<VaultEntryResponse> results = vaultService.searchEntries(
        "testuser", null, null, null, null, null, "createdAt", "desc");

    assertNotNull(results);
    assertEquals(2, results.size());
    // entry (2026) should come first with desc sort
    assertEquals("Test Entry", results.get(0).getTitle());
    assertEquals("Zebra Entry", results.get(1).getTitle());
  }

  // ===== Read-Only Mode Tests =====

  @Test
  void createEntry_ShouldThrowException_WhenReadOnlyModeEnabled() {
    UserSettings readOnlySettings = UserSettings.builder()
        .user(user).readOnlyMode(true).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(readOnlySettings));

    VaultEntryRequest request = new VaultEntryRequest();
    request.setTitle("New Entry");
    request.setCategoryId(1L);

    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> vaultService.createEntry("testuser", request));
    assertTrue(ex.getMessage().contains("read-only mode"));
    verify(vaultEntryRepository, never()).save(any());
  }

  @Test
  void updateEntry_ShouldThrowException_WhenReadOnlyModeEnabled() {
    UserSettings readOnlySettings = UserSettings.builder()
        .user(user).readOnlyMode(true).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(readOnlySettings));

    VaultEntryRequest request = new VaultEntryRequest();
    request.setTitle("Updated Title");

    assertThrows(IllegalStateException.class,
        () -> vaultService.updateEntry("testuser", 1L, request));
    verify(vaultEntryRepository, never()).save(any());
  }

  @Test
  void deleteEntry_ShouldThrowException_WhenReadOnlyModeEnabled() {
    UserSettings readOnlySettings = UserSettings.builder()
        .user(user).readOnlyMode(true).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(readOnlySettings));

    assertThrows(IllegalStateException.class,
        () -> vaultService.deleteEntry("testuser", 1L));
    verify(vaultEntryRepository, never()).save(any());
  }

  @Test
  void toggleFavorite_ShouldThrowException_WhenReadOnlyModeEnabled() {
    UserSettings readOnlySettings = UserSettings.builder()
        .user(user).readOnlyMode(true).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(readOnlySettings));

    assertThrows(IllegalStateException.class,
        () -> vaultService.toggleFavorite("testuser", 1L));
    verify(vaultEntryRepository, never()).save(any());
  }

  @Test
  void bulkDelete_ShouldThrowException_WhenReadOnlyModeEnabled() {
    UserSettings readOnlySettings = UserSettings.builder()
        .user(user).readOnlyMode(true).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(readOnlySettings));

    assertThrows(IllegalStateException.class,
        () -> vaultService.bulkDelete("testuser", List.of(1L, 2L)));
    verify(vaultEntryRepository, never()).saveAll(any());
  }

  @Test
  void createEntry_ShouldSucceed_WhenReadOnlyModeDisabled() {
    UserSettings normalSettings = UserSettings.builder()
        .user(user).readOnlyMode(false).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(normalSettings));
    when(categoryRepository.findById(1L)).thenReturn(Optional.of(category));
    when(folderRepository.findById(1L)).thenReturn(Optional.of(folder));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.encrypt(anyString(), any())).thenReturn("encrypted");
    when(vaultEntryRepository.save(any(VaultEntry.class))).thenReturn(entry);

    VaultEntryRequest request = new VaultEntryRequest();
    request.setTitle("Test Entry");
    request.setCategoryId(1L);
    request.setFolderId(1L);
    request.setPassword("password");
    request.setUsername("user");

    VaultEntryResponse response = vaultService.createEntry("testuser", request);

    assertNotNull(response);
    verify(vaultEntryRepository).save(any(VaultEntry.class));
  }

  @Test
  void getAllEntries_ShouldReturnList_WhenUserExists() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getAllEntries("testuser");

    assertNotNull(response);
    assertEquals(1, response.size());
    assertEquals("Test Entry", response.get(0).getTitle());
  }

  @Test
  void updateEntry_ShouldUpdateFields_WhenValidRequest() {
    VaultEntryRequest request = new VaultEntryRequest();
    request.setTitle("Updated Title");
    request.setPassword("newpass");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty()); // No settings implies generic defaults
                                                                                // (RW)
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.encrypt(eq("newpass"), any())).thenReturn("encryptedNew");
    when(vaultEntryRepository.save(any(VaultEntry.class))).thenReturn(entry);

    VaultEntryResponse response = vaultService.updateEntry("testuser", 1L, request);

    assertNotNull(response);
    assertEquals("Updated Title", response.getTitle());
    verify(vaultSnapshotService).createSnapshot(any(VaultEntry.class)); // Verifies snapshot creation on password change
    verify(vaultEntryRepository).save(entry);
  }

  @Test
  void deleteEntry_ShouldSoftDelete_WhenFound() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());

    vaultService.deleteEntry("testuser", 1L);

    assertTrue(entry.getIsDeleted());
    assertNotNull(entry.getDeletedAt());
    verify(vaultEntryRepository).save(entry);
    verify(auditLogService).logAction(eq("testuser"), any(), anyString());
  }

  @Test
  void getFavorites_ShouldReturnOnlyFavorites() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndIsFavoriteTrueAndIsDeletedFalse(1L)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getFavorites("testuser");

    assertNotNull(response);
    assertEquals(1, response.size());
  }

  @Test
  void getEntriesByFolder_ShouldReturnFolderEntries() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByUserIdAndFolderIdAndIsDeletedFalse(1L, 1L)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getEntriesByFolder("testuser", 1L);

    assertNotNull(response);
    assertEquals(1, response.size());
  }

  @Test
  void getEntriesByCategory_ShouldReturnCategoryEntries_WhenValid() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.searchEntries(1L, null, 1L, null, null, null)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getEntriesByCategory("testuser", 1L);

    assertNotNull(response);
    assertEquals(1, response.size());
    verify(vaultEntryRepository).searchEntries(1L, null, 1L, null, null, null);
  }

  @Test
  void getEntriesByCategory_ShouldReturnEmpty_WhenDuressMode() {
    org.springframework.security.core.Authentication auth = mock(
        org.springframework.security.core.Authentication.class);
    when(auth.getCredentials()).thenReturn("duressToken");
    org.springframework.security.core.context.SecurityContext securityContext = mock(
        org.springframework.security.core.context.SecurityContext.class);
    when(securityContext.getAuthentication()).thenReturn(auth);
    org.springframework.security.core.context.SecurityContextHolder.setContext(securityContext);

    when(jwtTokenProvider.isDuressToken("duressToken")).thenReturn(true);

    List<VaultEntryResponse> response = vaultService.getEntriesByCategory("testuser", 1L);

    assertNotNull(response);
    assertTrue(response.isEmpty());
    verify(vaultEntryRepository, never()).searchEntries(any(), any(), any(), any(), any(), any());
  }

  @Test
  void getRecentEntries_ShouldReturnEntries() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findTop10ByUserIdAndIsDeletedFalseOrderByCreatedAtDesc(1L)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getRecentEntries("testuser");

    assertNotNull(response);
    assertEquals(1, response.size());
  }

  @Test
  void getRecentlyUsedEntries_ShouldReturnEntries() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findTop10ByUserIdAndIsDeletedFalseOrderByUpdatedAtDesc(1L)).thenReturn(List.of(entry));

    List<VaultEntryResponse> response = vaultService.getRecentlyUsedEntries("testuser");

    assertNotNull(response);
    assertEquals(1, response.size());
  }

  @Test
  void toggleSensitive_ShouldToggleFlag_WhenEntryExists() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(vaultEntryRepository.save(any(VaultEntry.class))).thenAnswer(invocation -> invocation.getArgument(0));

    // Initial state is false
    VaultEntryResponse response = vaultService.toggleSensitive("testuser", 1L);

    assertNotNull(response);
    assertTrue(entry.getIsHighlySensitive());
    verify(vaultEntryRepository).save(any(VaultEntry.class));
    verify(auditLogService).logAction(eq("testuser"), any(), anyString());
  }

  @Test
  void bulkDelete_ShouldDeleteAll_WhenOwnedByUser() {
    VaultEntry entry2 = VaultEntry.builder().id(2L).user(user).build();
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());
    when(vaultEntryRepository.findAllById(List.of(1L, 2L))).thenReturn(List.of(entry, entry2));

    vaultService.bulkDelete("testuser", List.of(1L, 2L));

    assertTrue(entry.getIsDeleted());
    assertTrue(entry2.getIsDeleted());
    verify(vaultEntryRepository).saveAll(anyList());
    verify(auditLogService, times(2)).logAction(eq("testuser"), any(), anyString());
  }

  @Test
  void getPassword_ShouldReturnPassword_WhenNotSensitive() {
    entry.setIsHighlySensitive(false);
    entry.setPassword("encryptedPass");
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
    when(encryptionService.decrypt(anyString(), any())).thenReturn("decryptedPass");

    String password = vaultService.getPassword("testuser", 1L);

    assertEquals("decryptedPass", password);
    verify(auditLogService).logAction(eq("testuser"), any(), anyString());
  }

  @Test
  void getPassword_ShouldThrowException_WhenSensitive() {
    entry.setIsHighlySensitive(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));

    assertThrows(AuthenticationException.class, () -> vaultService.getPassword("testuser", 1L));
  }

  @Test
  void getAllEntries_ShouldReturnDummyVault_WhenInDuressMode() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    org.springframework.security.core.Authentication auth = mock(
        org.springframework.security.core.Authentication.class);
    when(auth.getCredentials()).thenReturn("duressToken");
    org.springframework.security.core.context.SecurityContext securityContext = mock(
        org.springframework.security.core.context.SecurityContext.class);
    when(securityContext.getAuthentication()).thenReturn(auth);
    org.springframework.security.core.context.SecurityContextHolder.setContext(securityContext);

    when(jwtTokenProvider.isDuressToken("duressToken")).thenReturn(true);

    VaultEntry dummyEntry = VaultEntry.builder()
        .id(-1L).user(user).category(category).folder(folder).title("Bank Dummy")
        .username("dummy").password("dummy").isHighlySensitive(false).build();
    when(duressService.generateDummyVault(user)).thenReturn(List.of(dummyEntry));

    List<VaultEntryResponse> response = vaultService.getAllEntries("testuser");

    assertNotNull(response);
    assertEquals(1, response.size());
    assertEquals("Bank Dummy", response.get(0).getTitle());
  }

  @Test
  void createEntry_ShouldThrowException_WhenInDuressMode() {
    org.springframework.security.core.Authentication auth = mock(
        org.springframework.security.core.Authentication.class);
    when(auth.getCredentials()).thenReturn("duressToken");
    org.springframework.security.core.context.SecurityContext securityContext = mock(
        org.springframework.security.core.context.SecurityContext.class);
    when(securityContext.getAuthentication()).thenReturn(auth);
    org.springframework.security.core.context.SecurityContextHolder.setContext(securityContext);

    when(jwtTokenProvider.isDuressToken("duressToken")).thenReturn(true);

    VaultEntryRequest request = new VaultEntryRequest();
    AuthenticationException ex = assertThrows(AuthenticationException.class,
        () -> vaultService.createEntry("testuser", request));
    assertTrue(ex.getMessage().contains("duress"));
  }
}
