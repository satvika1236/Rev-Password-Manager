package com.revature.passwordmanager.service.backup.importers;

import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.service.security.EncryptionService;

import javax.crypto.SecretKey;
import java.util.List;

public interface Importer {
  List<VaultEntry> parse(String csvData, User user, SecretKey key, EncryptionService encryptionService)
      throws Exception;

  String getSupportedSource();
}
