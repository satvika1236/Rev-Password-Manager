package com.revature.passwordmanager.service.security;

import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class DuressService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private static final SecureRandom RANDOM = new SecureRandom();

  private static final String[] DUMMY_TITLES = {
      "Email", "Social Media", "Banking", "Shopping", "Streaming",
      "Cloud Storage", "Gaming", "News", "Travel", "Fitness"
  };
  private static final String[] DUMMY_URLS = {
      "https://mail.example.com", "https://social.example.com",
      "https://bank.example.com", "https://shop.example.com",
      "https://stream.example.com", "https://cloud.example.com"
  };

  @Transactional
  public void setDuressPassword(String username, String duressPassword) {
    User user = userRepository.findByUsernameOrThrow(username);
    user.setDuressPasswordHash(passwordEncoder.encode(duressPassword));
    userRepository.save(user);
  }

  public boolean isDuressLogin(String username, String password) {
    User user = userRepository.findByUsername(username)
        .or(() -> userRepository.findByEmail(username))
        .orElse(null);
    if (user == null || user.getDuressPasswordHash() == null) {
      return false;
    }
    return passwordEncoder.matches(password, user.getDuressPasswordHash());
  }

  public List<VaultEntry> generateDummyVault(User user) {
    List<VaultEntry> dummyEntries = new ArrayList<>();

    for (int i = 0; i < 5; i++) {
      VaultEntry entry = VaultEntry.builder()
          .id((long) -(i + 1))
          .user(user)
          .title(DUMMY_TITLES[RANDOM.nextInt(DUMMY_TITLES.length)])
          .username("user" + RANDOM.nextInt(1000) + "@example.com")
          .password("***encrypted***")
          .websiteUrl(DUMMY_URLS[RANDOM.nextInt(DUMMY_URLS.length)])
          .notes("")
          .createdAt(LocalDateTime.now().minusDays(RANDOM.nextInt(365)))
          .updatedAt(LocalDateTime.now().minusDays(RANDOM.nextInt(30)))
          .build();
      dummyEntries.add(entry);
    }
    return dummyEntries;
  }
}
