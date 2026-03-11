package com.revature.passwordmanager.service.user;

import com.revature.passwordmanager.dto.request.UserSettingsRequest;
import com.revature.passwordmanager.dto.response.UserSettingsResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.user.UserSettings;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.UserSettingsRepository;
import com.revature.passwordmanager.service.user.UserSettingsService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserSettingsServiceTest {

  @Mock
  private UserSettingsRepository userSettingsRepository;
  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private UserSettingsService userSettingsService;

  private User user;
  private UserSettings settings;

  @BeforeEach
  void setUp() {
    user = User.builder().id(1L).username("testuser").build();
    settings = UserSettings.builder()
        .user(user)
        .theme("SYSTEM")
        .language("en-US")
        .autoLogoutMinutes(15)
        .build();
  }

  @Test
  void getSettings_ShouldReturnDefaults_WhenNoSettingsExist() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());
    when(userSettingsRepository.save(any(UserSettings.class))).thenReturn(settings);

    UserSettingsResponse response = userSettingsService.getSettings("testuser");

    assertNotNull(response);
    assertEquals("SYSTEM", response.getTheme());
    verify(userSettingsRepository).save(any(UserSettings.class));
  }

  @Test
  void getSettings_ShouldReturnExisting_WhenSettingsExist() {
    settings.setTheme("DARK");
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(settings));

    UserSettingsResponse response = userSettingsService.getSettings("testuser");

    assertEquals("DARK", response.getTheme());
    verify(userSettingsRepository, never()).save(any(UserSettings.class));
  }

  @Test
  void updateSettings_ShouldUpdateFields() {
    UserSettingsRequest request = new UserSettingsRequest();
    request.setTheme("LIGHT");
    request.setAutoLogoutMinutes(30);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(settings));
    when(userSettingsRepository.save(any(UserSettings.class))).thenAnswer(i -> i.getArguments()[0]);

    UserSettingsResponse response = userSettingsService.updateSettings("testuser", request);

    assertEquals("LIGHT", response.getTheme());
    assertEquals(30, response.getAutoLogoutMinutes());
    assertEquals("en-US", response.getLanguage()); // Unchanged
  }

  @Test
  void updateSettings_ShouldEnableReadOnlyMode() {
    UserSettingsRequest request = new UserSettingsRequest();
    request.setReadOnlyMode(true);

    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(settings));
    when(userSettingsRepository.save(any(UserSettings.class))).thenAnswer(i -> i.getArguments()[0]);

    UserSettingsResponse response = userSettingsService.updateSettings("testuser", request);

    assertTrue(response.getReadOnlyMode());
  }

  @Test
  void getSettings_ShouldReturnReadOnlyModeStatus() {
    settings.setReadOnlyMode(true);
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(userSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(settings));

    UserSettingsResponse response = userSettingsService.getSettings("testuser");

    assertTrue(response.getReadOnlyMode());
  }
}
