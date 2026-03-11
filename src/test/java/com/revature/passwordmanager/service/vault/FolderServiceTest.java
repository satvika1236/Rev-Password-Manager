package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.FolderDTO;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Folder;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.vault.FolderService;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class FolderServiceTest {

  @Mock
  private FolderRepository folderRepository;

  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private FolderService folderService;

  private User user;
  private Folder folder;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setId(1L);
    user.setUsername("testuser");

    folder = new Folder();
    folder.setId(1L);
    folder.setName("Test Folder");
    folder.setUser(user);
    folder.setSubfolders(Collections.emptyList());
  }

  @Test
  void getFolders_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByUserAndParentFolderIsNull(user)).thenReturn(Collections.singletonList(folder));

    List<FolderDTO> result = folderService.getFolders("testuser");

    assertNotNull(result);
    assertEquals(1, result.size());
    assertEquals("Test Folder", result.get(0).getName());
  }

  @Test
  void createFolder_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.save(any(Folder.class))).thenReturn(folder);

    FolderDTO result = folderService.createFolder("Test Folder", null, "testuser");

    assertNotNull(result);
    assertEquals("Test Folder", result.getName());
    verify(folderRepository).save(any(Folder.class));
  }

  @Test
  void createSubfolder_Success() {
    Folder parentFolder = new Folder();
    parentFolder.setId(2L);
    parentFolder.setUser(user);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByIdAndUser(2L, user)).thenReturn(Optional.of(parentFolder));

    Folder subfolder = new Folder();
    subfolder.setName("Subfolder");
    subfolder.setParentFolder(parentFolder);
    subfolder.setUser(user);
    subfolder.setSubfolders(Collections.emptyList()); // Initialize list to avoid NPE in mapping

    when(folderRepository.save(any(Folder.class))).thenReturn(subfolder);

    FolderDTO result = folderService.createFolder("Subfolder", 2L, "testuser");

    assertNotNull(result);
    assertEquals("Subfolder", result.getName());
    assertEquals(2L, result.getParentFolderId());
  }

  @Test
  void updateFolder_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByIdAndUser(1L, user)).thenReturn(Optional.of(folder));
    when(folderRepository.save(any(Folder.class))).thenReturn(folder);

    FolderDTO result = folderService.updateFolder(1L, "Updated Name", "testuser");

    assertNotNull(result);
    verify(folderRepository).save(folder);
  }

  @Test
  void moveFolder_Success() {
    Folder newParent = new Folder();
    newParent.setId(2L);
    newParent.setUser(user);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByIdAndUser(1L, user)).thenReturn(Optional.of(folder));
    when(folderRepository.findByIdAndUser(2L, user)).thenReturn(Optional.of(newParent));
    when(folderRepository.save(any(Folder.class))).thenReturn(folder);

    FolderDTO result = folderService.moveFolder(1L, 2L, "testuser");

    assertNotNull(result);
    verify(folderRepository).save(folder);
  }

  @Test
  void moveFolder_CircularDependency_ThrowsException() {
    // Trying to move folder into itself
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByIdAndUser(1L, user)).thenReturn(Optional.of(folder));

    assertThrows(IllegalArgumentException.class, () -> folderService.moveFolder(1L, 1L, "testuser"));
  }

  @Test
  void deleteFolder_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(folderRepository.findByIdAndUser(1L, user)).thenReturn(Optional.of(folder));

    folderService.deleteFolder(1L, "testuser");

    verify(folderRepository).delete(folder);
  }
}
