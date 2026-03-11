package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.response.SnapshotResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Category;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.model.vault.VaultSnapshot;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.repository.VaultSnapshotRepository;

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
class VaultSnapshotServiceTest {

  @Mock
  private VaultSnapshotRepository vaultSnapshotRepository;
  @Mock
  private VaultEntryRepository vaultEntryRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private VaultSnapshotService vaultSnapshotService;

  private User user;
  private VaultEntry entry;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .username("testuser")
        .masterPasswordHash("hash")
        .salt("salt")
        .build();

    Category category = Category.builder().id(1L).name("Login").build();

    entry = VaultEntry.builder()
        .id(1L)
        .user(user)
        .category(category)
        .title("Test Entry")
        .username("encryptedUser")
        .password("encryptedOldPassword")
        .websiteUrl("https://example.com")
        .isFavorite(false)
        .isHighlySensitive(false)
        .build();
  }

  @Test
  void createSnapshot_ShouldSaveOldPassword() {
    when(vaultSnapshotRepository.save(any(VaultSnapshot.class)))
        .thenAnswer(i -> i.getArgument(0));

    vaultSnapshotService.createSnapshot(entry);

    verify(vaultSnapshotRepository).save(argThat(snapshot -> {
      assertEquals("encryptedOldPassword", snapshot.getPassword());
      assertEquals(entry, snapshot.getVaultEntry());
      assertNotNull(snapshot.getChangedAt());
      return true;
    }));
  }

  @Test
  void getHistory_ShouldReturnSnapshotsInDescOrder() {
    VaultSnapshot snap1 = VaultSnapshot.builder()
        .id(1L).vaultEntry(entry).password("encOld1")
        .changedAt(LocalDateTime.of(2026, 1, 1, 10, 0)).build();
    VaultSnapshot snap2 = VaultSnapshot.builder()
        .id(2L).vaultEntry(entry).password("encOld2")
        .changedAt(LocalDateTime.of(2026, 2, 1, 10, 0)).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultEntryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(entry));
    when(vaultSnapshotRepository.findByVaultEntryIdOrderByChangedAtDesc(1L))
        .thenReturn(List.of(snap2, snap1));

    List<SnapshotResponse> results = vaultSnapshotService.getHistory("testuser", 1L);

    assertNotNull(results);
    assertEquals(2, results.size());
    // Newest first
    assertEquals(LocalDateTime.of(2026, 2, 1, 10, 0), results.get(0).getChangedAt());
    assertEquals(LocalDateTime.of(2026, 1, 1, 10, 0), results.get(1).getChangedAt());
  }

  @Test
  void getAllSnapshots_ShouldReturnList() {
    VaultSnapshot snap = VaultSnapshot.builder()
        .id(1L).vaultEntry(entry).password("encryptedSecret")
        .changedAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultSnapshotRepository.findByVaultEntryUserIdOrderByChangedAtDesc(1L))
        .thenReturn(List.of(snap));

    List<SnapshotResponse> results = vaultSnapshotService.getAllSnapshots("testuser");

    assertEquals(1, results.size());
    assertEquals("******", results.get(0).getPassword());
  }

  @Test
  void restoreSnapshot_ShouldRestorePassword() {
    VaultSnapshot snap = VaultSnapshot.builder()
        .id(1L).vaultEntry(entry).password("encryptedSecret")
        .changedAt(LocalDateTime.now()).build();

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(vaultSnapshotRepository.findById(1L)).thenReturn(Optional.of(snap));
    when(vaultSnapshotRepository.save(any())).thenAnswer(i -> i.getArgument(0)); // createSnapshot mock

    vaultSnapshotService.restoreSnapshot("testuser", 1L);

    verify(vaultEntryRepository).save(argThat(e -> {
      assertEquals("encryptedSecret", e.getPassword());
      assertNotNull(e.getUpdatedAt());
      return true;
    }));
  }
}
