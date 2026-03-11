package com.revature.passwordmanager.service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.revature.passwordmanager.service.security.RateLimitService;

import static org.junit.jupiter.api.Assertions.*;

class RateLimitServiceTest {

  private RateLimitService rateLimitService;

  @BeforeEach
  void setUp() {
    rateLimitService = new RateLimitService();
  }

  @Test
  void isAllowed_GeneralRequest_ShouldAllowUnder60() {
    String ip = "192.168.1.1";
    for (int i = 0; i < 60; i++) {
      assertTrue(rateLimitService.isAllowed(ip, "/api/vault"));
    }
    assertFalse(rateLimitService.isAllowed(ip, "/api/vault"));
  }

  @Test
  void isAllowed_AuthRequest_ShouldAllowUnder10() {
    String ip = "192.168.1.2";
    for (int i = 0; i < 10; i++) {
      assertTrue(rateLimitService.isAllowed(ip, "/api/auth/login"));
    }
    assertFalse(rateLimitService.isAllowed(ip, "/api/auth/login"));
  }

  @Test
  void isAllowed_DifferentIPs_ShouldTrackSeparately() {
    for (int i = 0; i < 10; i++) {
      rateLimitService.isAllowed("10.0.0.1", "/api/auth/login");
    }
    assertTrue(rateLimitService.isAllowed("10.0.0.2", "/api/auth/login"));
    assertFalse(rateLimitService.isAllowed("10.0.0.1", "/api/auth/login"));
  }

  @Test
  void getRemainingRequests_ShouldDecrement() {
    String ip = "192.168.1.3";
    rateLimitService.isAllowed(ip, "/api/vault");
    int remaining = rateLimitService.getRemainingRequests(ip, "/api/vault");
    assertEquals(59, remaining);
  }
}
