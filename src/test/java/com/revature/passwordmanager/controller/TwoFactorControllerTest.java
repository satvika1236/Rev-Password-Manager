package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.response.TwoFactorSetupResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.auth.TwoFactorService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = TwoFactorController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class
})
@Import(SecurityConfig.class)
@AutoConfigureMockMvc(addFilters = false)
public class TwoFactorControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private TwoFactorService twoFactorService;

  @MockBean
  private SessionService sessionService;

  @MockBean
  private UserRepository userRepository;

  @MockBean
  private JwtTokenProvider jwtTokenProvider;

  @MockBean
  private CustomUserDetailsService customUserDetailsService;

  @MockBean
  private PasswordEncoder passwordEncoder;

  @MockBean
  private RateLimitService rateLimitService;

  @MockBean
  private ClientIpUtil clientIpUtil;

  @BeforeEach
  void setUp() {
    Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
    Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString())).thenReturn(true);
    Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString())).thenReturn(100);
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testSetup2FA_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");
    user.setEmail("test@example.com");

    when(jwtTokenProvider.validateToken(anyString())).thenReturn(true);
    when(jwtTokenProvider.getUsernameFromToken(anyString())).thenReturn("testuser");

    TwoFactorSetupResponse response = TwoFactorSetupResponse.builder()
            .secretKey("secret")
            .qrCodeUrl("qr-code-url")
            .build();

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(twoFactorService.setup2FA(any(User.class))).thenReturn(response);

    mockMvc.perform(post("/api/2fa/setup")
                    .header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.secretKey").value("secret"))
            .andExpect(jsonPath("$.qrCodeUrl").value("qr-code-url"));
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testVerifySetup_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    doNothing().when(twoFactorService).verifySetup(any(User.class), anyString());
    when(twoFactorService.getRecoveryCodes(any(User.class))).thenReturn(Collections.singletonList("backup-code"));

    mockMvc.perform(post("/api/2fa/verify-setup")
                    .header("Authorization", "Bearer token")
                    .param("code", "123456"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.message").value("2FA enabled successfully"))
            .andExpect(jsonPath("$.backupCodes[0]").value("backup-code"));
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testDisable2FA_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    doNothing().when(twoFactorService).disable2FA(any(User.class));

    mockMvc.perform(post("/api/2fa/disable")
                    .header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("2FA disabled successfully"));
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testGetStatus_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");
    user.set2faEnabled(true);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

    mockMvc.perform(get("/api/2fa/status")
                    .header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.enabled").value(true));
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testGetBackupCodes_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(twoFactorService.getRecoveryCodes(any(User.class))).thenReturn(
            List.of("CODE1", "CODE2", "CODE3"));

    mockMvc.perform(get("/api/2fa/backup-codes")
                    .header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0]").value("CODE1"))
            .andExpect(jsonPath("$[1]").value("CODE2"))
            .andExpect(jsonPath("$[2]").value("CODE3"));
  }

  @Test
  @WithMockUser(username = "testuser")
  public void testRegenerateCodes_Success() throws Exception {
    User user = new User();
    user.setUsername("testuser");

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(twoFactorService.regenerateRecoveryCodes(any(User.class))).thenReturn(
            List.of("NEW1", "NEW2"));

    mockMvc.perform(post("/api/2fa/regenerate-codes")
                    .header("Authorization", "Bearer token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.message").value("Backup codes regenerated successfully"))
            .andExpect(jsonPath("$.backupCodes[0]").value("NEW1"))
            .andExpect(jsonPath("$.backupCodes[1]").value("NEW2"));
  }
}
