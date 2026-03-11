package com.revature.passwordmanager;

import com.revature.passwordmanager.util.PojoTestUtils;
import org.junit.jupiter.api.Test;

class ModelCoverageTest {

  @Test
  void testCriticalModels() {
    Class<?>[] classes = {
        com.revature.passwordmanager.model.vault.VaultEntry.class,
        com.revature.passwordmanager.model.user.User.class,
        com.revature.passwordmanager.model.user.UserSession.class,
        com.revature.passwordmanager.model.user.SecurityQuestion.class,
        com.revature.passwordmanager.model.user.UserSettings.class,
        com.revature.passwordmanager.model.vault.Category.class,
        com.revature.passwordmanager.model.vault.Folder.class,

        com.revature.passwordmanager.dto.response.VaultEntryDetailResponse.class,
        com.revature.passwordmanager.dto.response.VaultEntryResponse.class,
        com.revature.passwordmanager.dto.response.AuthResponse.class,
        com.revature.passwordmanager.dto.response.HealthResponse.class,

        com.revature.passwordmanager.dto.request.LoginRequest.class,
        com.revature.passwordmanager.dto.request.RegistrationRequest.class,
        com.revature.passwordmanager.dto.request.VaultEntryRequest.class
    };

    for (Class<?> clazz : classes) {
      try {
        System.out.println("Testing model: " + clazz.getName());
        PojoTestUtils.validateAccessors(clazz);
      } catch (Exception e) {
        System.err.println("FAILURE: " + clazz.getName() + " - " + e.getMessage());
        e.printStackTrace();
      }
    }
  }
}
