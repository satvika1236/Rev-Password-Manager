package com.revature.passwordmanager.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DashboardResponse {
  private int totalVaultEntries;
  private int totalCategories;
  private int totalFolders;
  private int totalFavorites;
  private int weakPasswordsCount;
  private int reusedPasswordsCount;
  private int oldPasswordsCount;
  private int unreadNotifications;
}
