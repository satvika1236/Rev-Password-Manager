package com.revature.passwordmanager;

import com.revature.passwordmanager.service.dashboard.PasswordStrengthDashboardService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class DashboardErrorTest {

  @Autowired
  private PasswordStrengthDashboardService dashboardService;

  @Test
  public void printDashboardError() {
    try {
      System.out.println("Starting dashboard test for user Reddy...");
      dashboardService.getPasswordAge("Reddy");
      System.out.println("No error thrown!");
    } catch (Exception e) {
      e.printStackTrace();
      System.err.println("DASHBOARD ERROR CAUGHT:");
      System.err.println(e.getMessage());
    }
  }
}
