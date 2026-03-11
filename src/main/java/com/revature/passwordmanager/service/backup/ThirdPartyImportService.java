





package com.revature.passwordmanager.service.backup;

import com.revature.passwordmanager.dto.request.ThirdPartyImportRequest;
import com.revature.passwordmanager.dto.response.ImportResult;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.service.vault.VaultService;
import com.revature.passwordmanager.service.backup.importers.Importer;
import com.revature.passwordmanager.service.backup.importers.ImporterFactory;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ThirdPartyImportService {

  private static final Logger logger = LoggerFactory.getLogger(ThirdPartyImportService.class);

  private final UserRepository userRepository;
  private final EncryptionService encryptionService;
  private final VaultService vaultService;
  private final ImporterFactory importerFactory;

  @Transactional
  public ImportResult importFromThirdParty(String username, ThirdPartyImportRequest request) {
    User user = userRepository.findByUsernameOrThrow(username);

    // Derive key using the same method as VaultService (PBKDF2 with master password
    // hash and salt)
    SecretKey key = encryptionService.deriveKey(user.getMasterPasswordHash(), user.getSalt());

    try {
      Importer importer = importerFactory.getImporter(request.getSource());
      List<VaultEntry> entries = importer.parse(request.getData(), user, key, encryptionService);

      if (!entries.isEmpty()) {
        vaultService.bulkInsert(user.getUsername(), entries);
      }

      return ImportResult.builder()
          .totalProcessed(entries.size())
          .successCount(entries.size())
          .failCount(0)
          .message(request.getSource() + " import completed")
          .build();

    } catch (IllegalArgumentException e) {
      return ImportResult.builder()
          .totalProcessed(0).successCount(0).failCount(0)
          .message(e.getMessage())
          .build();
    } catch (Exception e) {
      logger.error("Failed to parse CSV for source {}: {}", request.getSource(), e.getMessage());
      return ImportResult.builder()
          .totalProcessed(0).successCount(0).failCount(1)
          .message(request.getSource() + " CSV parsing error")
          .build();
    }
  }

  @Transactional(readOnly = true)
  public List<String> getSupportedFormats() {
    return importerFactory.getSupportedFormats();
  }
}
