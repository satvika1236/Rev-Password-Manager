package com.revature.passwordmanager.service.backup.importers;

import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.service.security.EncryptionService;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.StringReader;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Component
public class LastPassImporter implements Importer {

  @Override
  public String getSupportedSource() {
    return "LASTPASS";
  }

  @Override
  public List<VaultEntry> parse(String csvData, User user, SecretKey key, EncryptionService encryptionService)
      throws Exception {
    List<VaultEntry> entries = new ArrayList<>();

    try (BufferedReader reader = new BufferedReader(new StringReader(csvData))) {
      @SuppressWarnings("unused") // Ignore header row
      String header = reader.readLine();
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.trim().isEmpty())
          continue;
        String[] parts = line.split(",", -1);
        VaultEntry entry = VaultEntry.builder()
            .user(user)
            .websiteUrl(parts.length > 0 ? parts[0].trim() : "")
            .username(parts.length > 1 ? parts[1].trim() : "")
            .password(parts.length > 2 ? encryptionService.encrypt(parts[2].trim(), key) : "")
            .notes(parts.length > 4 ? parts[4].trim() : "")
            .title(parts.length > 5 ? parts[5].trim() : "")
            .createdAt(LocalDateTime.now())
            .updatedAt(LocalDateTime.now())
            .build();
        entries.add(entry);
      }
    }
    return entries;
  }
}
