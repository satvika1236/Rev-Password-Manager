package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.FolderDTO;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Folder;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class FolderService {

  private final FolderRepository folderRepository;
  private final UserRepository userRepository;

  @Transactional(readOnly = true)
  public List<FolderDTO> getFolders(String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    List<Folder> folders = folderRepository.findByUserAndParentFolderIsNull(user);
    return folders.stream().map(this::mapToDTO).collect(Collectors.toList());
  }

  @Transactional(readOnly = true)
  public FolderDTO getFolderById(Long id, String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    Folder folder = folderRepository.findByIdAndUser(id, user)
        .orElseThrow(() -> new ResourceNotFoundException("Folder", "id", id));
    return mapToDTO(folder);
  }

  @Transactional
  public FolderDTO createFolder(String name, Long parentFolderId, String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    Folder parentFolder = null;
    if (parentFolderId != null) {
      parentFolder = folderRepository.findByIdAndUser(parentFolderId, user)
          .orElseThrow(() -> new ResourceNotFoundException("Parent Folder", "id", parentFolderId));
    }

    Folder folder = Folder.builder()
        .name(name)
        .user(user)
        .parentFolder(parentFolder)
        .build();

    Folder savedFolder = folderRepository.save(folder);
    return mapToDTO(savedFolder);
  }

  @Transactional
  public FolderDTO updateFolder(Long id, String name, String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    Folder folder = folderRepository.findByIdAndUser(id, user)
        .orElseThrow(() -> new ResourceNotFoundException("Folder", "id", id));

    folder.setName(name);
    Folder savedFolder = folderRepository.save(folder);
    return mapToDTO(savedFolder);
  }

  @Transactional
  public FolderDTO moveFolder(Long id, Long newParentId, String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    Folder folder = folderRepository.findByIdAndUser(id, user)
        .orElseThrow(() -> new ResourceNotFoundException("Folder", "id", id));

    Folder newParent = null;
    if (newParentId != null) {

      if (folder.getId().equals(newParentId)) {
        throw new IllegalArgumentException("Cannot move a folder into itself");
      }

      newParent = folderRepository.findByIdAndUser(newParentId, user)
          .orElseThrow(() -> new ResourceNotFoundException("Parent Folder", "id", newParentId));
    }

    folder.setParentFolder(newParent);
    Folder savedFolder = folderRepository.save(folder);
    return mapToDTO(savedFolder);
  }

  @Transactional
  public void deleteFolder(Long id, String username) {
    User user = userRepository.findByUsernameOrThrow(username);
    Folder folder = folderRepository.findByIdAndUser(id, user)
        .orElseThrow(() -> new ResourceNotFoundException("Folder", "id", id));

    folderRepository.delete(folder);
  }

  private FolderDTO mapToDTO(Folder folder) {
    return FolderDTO.builder()
        .id(folder.getId())
        .name(folder.getName())
        .parentFolderId(folder.getParentFolder() != null ? folder.getParentFolder().getId() : null)
        .subfolders(folder.getSubfolders().stream().map(this::mapToDTO).collect(Collectors.toList()))
        .createdAt(folder.getCreatedAt())
        .updatedAt(folder.getUpdatedAt())
        .build();
  }

}
