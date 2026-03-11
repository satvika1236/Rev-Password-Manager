package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DuressServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private DuressService duressService;

  private User user;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setId(1L);
    user.setUsername("testuser");
  }

  @Test
  void setDuressPassword_ShouldSaveHash_WhenUserExists() {
    when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(user);
    when(passwordEncoder.encode("duress123")).thenReturn("hashedDuress");

    duressService.setDuressPassword("testuser", "duress123");

    assertEquals("hashedDuress", user.getDuressPasswordHash());
    verify(userRepository).save(user);
  }

  @Test
  void isDuressLogin_ShouldReturnTrue_WhenCredentialsMatch() {
    user.setDuressPasswordHash("hashedDuress");
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(passwordEncoder.matches("duress123", "hashedDuress")).thenReturn(true);

    assertTrue(duressService.isDuressLogin("testuser", "duress123"));
  }

  @Test
  void isDuressLogin_ShouldReturnFalse_WhenPasswordMismatch() {
    user.setDuressPasswordHash("hashedDuress");
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(passwordEncoder.matches("wrongpass", "hashedDuress")).thenReturn(false);

    assertFalse(duressService.isDuressLogin("testuser", "wrongpass"));
  }

  @Test
  void isDuressLogin_ShouldReturnFalse_WhenNoDuressPasswordSet() {
    user.setDuressPasswordHash(null);
    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

    assertFalse(duressService.isDuressLogin("testuser", "plainpass"));
  }

  @Test
  void generateDummyVault_ShouldReturnFiveEntries() {
    List<VaultEntry> dummyVault = duressService.generateDummyVault(user);

    assertNotNull(dummyVault);
    assertEquals(5, dummyVault.size());
    for (VaultEntry entry : dummyVault) {
      assertEquals(user, entry.getUser());
      assertNotNull(entry.getTitle());
      assertNotNull(entry.getWebsiteUrl());
      assertEquals("***encrypted***", entry.getPassword());
    }
  }
}
