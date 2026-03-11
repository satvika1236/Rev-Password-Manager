package com.revature.passwordmanager.service.user;

import com.revature.passwordmanager.dto.request.ChangePasswordRequest;
import com.revature.passwordmanager.dto.request.UpdateProfileRequest;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.FolderRepository;
import com.revature.passwordmanager.repository.NotificationRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.service.security.SecurityAuditService;
import com.revature.passwordmanager.util.EncryptionUtil;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private VaultEntryRepository vaultEntryRepository;

  @Mock
  private CategoryRepository categoryRepository;

  @Mock
  private FolderRepository folderRepository;

  @Mock
  private NotificationRepository notificationRepository;

  @Mock
  private SecurityAuditService securityAuditService;

  @Mock
  private EncryptionService encryptionService;

  @Mock
  private EncryptionUtil encryptionUtil;

  @InjectMocks
  private UserService userService;

  private User user;

  @BeforeEach
  void setUp() {
    user = User.builder()
        .id(1L)
        .email("test@example.com")
        .username("testuser")
        .masterPasswordHash("hashedOldPassword")
        .salt("randomSalt")
        .is2faEnabled(false)
        .createdAt(LocalDateTime.now())
        .build();
  }

  @Test
  void getUserProfile_Success() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    UserResponse response = userService.getUserProfile("testuser");

    assertNotNull(response);
    assertEquals("testuser", response.getUsername());
    assertEquals("test@example.com", response.getEmail());
    assertNull(response.getDeletionScheduledAt());
    verify(userRepository).findByUsernameOrThrow("testuser");
  }

  @Test
  void getUserProfile_WithDeletionScheduled() {
    LocalDateTime scheduledDate = LocalDateTime.now().plusDays(30);
    user.setDeletionScheduledAt(scheduledDate);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);

    UserResponse response = userService.getUserProfile("testuser");

    assertNotNull(response);
    assertEquals(scheduledDate, response.getDeletionScheduledAt());
  }

  @Test
  void getUserProfile_UserNotFound() {
    when(userRepository.findByUsernameOrThrow("unknown")).thenThrow(new ResourceNotFoundException("User not found"));

    assertThrows(ResourceNotFoundException.class, () -> userService.getUserProfile("unknown"));
  }

  @Test
  void changeMasterPassword_Success() {
    ChangePasswordRequest request = new ChangePasswordRequest();
    request.setOldPassword("oldPassword");
    request.setNewPassword("newSafePassword123!");

    SecretKey mockOldKey = mock(SecretKey.class);
    SecretKey mockNewKey = mock(SecretKey.class);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordEncoder.matches("oldPassword", "hashedOldPassword")).thenReturn(true);
    when(passwordEncoder.encode("newSafePassword123!")).thenReturn("hashedNewPassword");
    when(encryptionUtil.deriveKey("hashedOldPassword", "randomSalt")).thenReturn(mockOldKey);
    when(encryptionUtil.deriveKey("hashedNewPassword", "randomSalt")).thenReturn(mockNewKey);
    when(vaultEntryRepository.findByUserIdAndIsDeletedFalse(1L)).thenReturn(Collections.emptyList());

    userService.changeMasterPassword("testuser", request);

    verify(userRepository).save(any(User.class));
    verify(vaultEntryRepository).saveAll(any());
    assertEquals("hashedNewPassword", user.getMasterPasswordHash());
  }

  @Test
  void changeMasterPassword_InvalidOldPassword() {
    ChangePasswordRequest request = new ChangePasswordRequest();
    request.setOldPassword("wrongPassword");
    request.setNewPassword("newSafePassword123!");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordEncoder.matches("wrongPassword", "hashedOldPassword")).thenReturn(false);

    assertThrows(AuthenticationException.class, () -> userService.changeMasterPassword("testuser", request));
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  void updateProfile_Success() {
    UpdateProfileRequest request = new UpdateProfileRequest();
    request.setName("New Name");
    request.setPhoneNumber("1234567890");

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userRepository.save(any(User.class))).thenReturn(user);

    UserResponse response = userService.updateProfile("testuser", request);

    assertNotNull(response);
    verify(userRepository).save(user);
    assertEquals("New Name", user.getName());
    assertEquals("1234567890", user.getPhoneNumber());
  }
}
