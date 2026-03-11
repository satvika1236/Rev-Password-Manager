package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.FolderDTO;
import com.revature.passwordmanager.service.vault.FolderService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.revature.passwordmanager.dto.response.MessageResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;
import com.revature.passwordmanager.dto.response.VaultEntryResponse;
import com.revature.passwordmanager.service.vault.VaultService;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class FolderControllerTest {

  @Mock
  private FolderService folderService;

  @Mock
  private SecurityContext securityContext;

  @Mock
  private Authentication authentication;

  @InjectMocks
  private FolderController folderController;

  @Mock
  private VaultService vaultService;

  private FolderDTO folderDTO;

  @BeforeEach
  void setUp() {
    folderDTO = new FolderDTO();
    folderDTO.setId(1L);
    folderDTO.setName("Test Folder");

    SecurityContextHolder.setContext(securityContext);
  }

  @Test
  void getFolders_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    when(folderService.getFolders("testuser")).thenReturn(Collections.singletonList(folderDTO));

    ResponseEntity<List<FolderDTO>> response = folderController.getFolders();

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertEquals(1, response.getBody().size());
    assertEquals(1L, response.getBody().get(0).getId());
    assertEquals("Test Folder", response.getBody().get(0).getName());
  }

  @Test
  void createFolder_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    when(folderService.createFolder(anyString(), any(), anyString())).thenReturn(folderDTO);

    ResponseEntity<FolderDTO> response = folderController.createFolder("Test Folder", null);

    assertEquals(HttpStatus.CREATED, response.getStatusCode());
    assertEquals(1L, response.getBody().getId());
    assertEquals("Test Folder", response.getBody().getName());
  }

  @Test
  void updateFolder_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    when(folderService.updateFolder(anyLong(), anyString(), anyString())).thenReturn(folderDTO);

    ResponseEntity<FolderDTO> response = folderController.updateFolder(1L, "Updated Name");

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertEquals(1L, response.getBody().getId());
    assertEquals("Test Folder", response.getBody().getName());
  }

  @Test
  void deleteFolder_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    doNothing().when(folderService).deleteFolder(anyLong(), anyString());

    ResponseEntity<MessageResponse> response = folderController.deleteFolder(1L);

    assertEquals(HttpStatus.OK, response.getStatusCode());
  }

  @Test
  void getEntriesInFolder_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    when(vaultService.getEntriesByFolder(anyString(), anyLong())).thenReturn(Collections.emptyList());

    ResponseEntity<List<VaultEntryResponse>> response = folderController
        .getEntriesInFolder(1L);

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertNotNull(response.getBody());
    assertEquals(0, response.getBody().size());
  }

  @Test
  void getFolderById_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");
    when(folderService.getFolderById(anyLong(), anyString())).thenReturn(folderDTO);

    ResponseEntity<FolderDTO> response = folderController.getFolderById(1L);

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertEquals(1L, response.getBody().getId());
    assertEquals("Test Folder", response.getBody().getName());
  }

  @Test
  void moveFolder_Success() {
    when(securityContext.getAuthentication()).thenReturn(authentication);
    when(authentication.getName()).thenReturn("testuser");

    FolderDTO movedFolder = new FolderDTO();
    movedFolder.setId(1L);
    movedFolder.setName("Test Folder");

    when(folderService.moveFolder(anyLong(), anyLong(), anyString())).thenReturn(movedFolder);

    ResponseEntity<FolderDTO> response = folderController.moveFolder(1L, 2L);

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertNotNull(response.getBody());
    assertEquals(1L, response.getBody().getId());
    assertEquals("Test Folder", response.getBody().getName());
  }
}
