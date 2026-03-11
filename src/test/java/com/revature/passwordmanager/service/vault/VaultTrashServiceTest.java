package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.response.TrashEntryResponse;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Category;
import com.revature.passwordmanager.model.vault.Folder;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultTrashRepository;
import com.revature.passwordmanager.service.vault.VaultTrashService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultTrashServiceTest {

  @Mock
  private VaultTrashRepository vaultTrashRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private com.revature.passwordmanager.repository.VaultSnapshotRepository vaultSnapshotRepository;
  @Mock
  private com.revature.passwordmanager.repository.PasswordAnalysisRepository passwordAnalysisRepository;
  @Mock
  private com.revature.passwordmanager.service.notification.NotificationService notificationService;
  @Mock
  private com.revature.passwordmanager.repository.SecureShareRepository secureShareRepository;

  @InjectMocks
  private VaultTrashService vaultTrashService;

  private User user;
  private VaultEntry deletedEntry;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .username("testuser")
        .masterPasswordHash("hash")
        .salt("salt")
        .build();

    Category category = Category.builder().id(1L).name("Login").build();
    Folder folder = Folder.builder().id(1L).name("Work").build();

    deletedEntry = VaultEntry.builder()
        .id(1L)
        .user(user)
        .category(category)
        .folder(folder)
        .title("Deleted Entry")
        .username("encryptedUsername")
        .password("encryptedPassword")
        .websiteUrl("https://example.com")
        .isDeleted(true)
        .deletedAt(LocalDateTime.now().minusDays(5))
        .isHighlySensitive(false)
        .build();
  }

  @Test
  void getTrashEntries_ShouldReturnDeletedItems() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultTrashRepository.findByUserIdAndIsDeletedTrue(1L))
        .thenReturn(List.of(deletedEntry));

    List<TrashEntryResponse> results = vaultTrashService.getTrashEntries("testuser");

    assertNotNull(results);
    assertEquals(1, results.size());
    assertEquals("Deleted Entry", results.get(0).getTitle());
    assertNotNull(results.get(0).getDeletedAt());
    assertNotNull(results.get(0).getExpiresAt());
    assertTrue(results.get(0).getDaysRemaining() > 0);
  }

  @Test
  void restoreEntry_ShouldUndelete() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultTrashRepository.findByIdAndUserIdAndIsDeletedTrue(1L, 1L))
        .thenReturn(Optional.of(deletedEntry));
    when(vaultTrashRepository.save(any(VaultEntry.class))).thenAnswer(i -> i.getArgument(0));

    TrashEntryResponse response = vaultTrashService.restoreEntry("testuser", 1L);

    assertNotNull(response);
    assertFalse(deletedEntry.getIsDeleted());
    assertNull(deletedEntry.getDeletedAt());
    verify(vaultTrashRepository).save(deletedEntry);
  }

  @Test
  void permanentDelete_ShouldRemoveFromDB() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultTrashRepository.findByIdAndUserIdAndIsDeletedTrue(1L, 1L))
        .thenReturn(Optional.of(deletedEntry));

    vaultTrashService.permanentDelete("testuser", 1L);

    verify(vaultTrashRepository).delete(deletedEntry);
  }

  @Test
  void permanentDelete_ShouldThrow_WhenEntryNotFound() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultTrashRepository.findByIdAndUserIdAndIsDeletedTrue(99L, 1L))
        .thenReturn(Optional.empty());

    assertThrows(ResourceNotFoundException.class,
        () -> vaultTrashService.permanentDelete("testuser", 99L));
  }

  @Test
  void cleanupExpired_ShouldDeleteOldEntries() {
    VaultEntry expiredEntry = VaultEntry.builder()
        .id(2L).user(user).title("Expired")
        .username("enc").password("enc")
        .isDeleted(true)
        .deletedAt(LocalDateTime.now().minusDays(31))
        .isHighlySensitive(false)
        .build();

    when(vaultTrashRepository.findExpiredTrashEntries(any(LocalDateTime.class)))
        .thenReturn(List.of(expiredEntry));

    vaultTrashService.cleanupExpired();

    verify(vaultTrashRepository).deleteAll(List.of(expiredEntry));
  }
}
