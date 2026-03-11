package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.dto.request.AccountDeletionRequest;
import com.revature.passwordmanager.dto.request.ChangePasswordRequest;
import com.revature.passwordmanager.dto.request.UpdateSecurityQuestionsRequest;
import com.revature.passwordmanager.dto.request.ToggleReadOnlyRequest;
import com.revature.passwordmanager.dto.response.DashboardResponse;
import com.revature.passwordmanager.dto.response.HeatmapResponse;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.model.user.SecurityQuestion;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.analytics.AccessHeatmapService;
import com.revature.passwordmanager.service.auth.SecurityQuestionService;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.service.user.AccountDeletionService;
import com.revature.passwordmanager.service.user.UserService;
import com.revature.passwordmanager.service.user.UserSettingsService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = UserController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class
})
@Import(SecurityConfig.class)
public class UserControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private UserService userService;

        @MockBean
        private AccountDeletionService accountDeletionService;

        @MockBean
        private JwtTokenProvider jwtTokenProvider;

        @MockBean
        private CustomUserDetailsService customUserDetailsService;

        @MockBean
        private SessionService sessionService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private UserRepository userRepository;

        @MockBean
        private SecurityQuestionService securityQuestionService;

        @MockBean
        private PasswordEncoder passwordEncoder;

        @MockBean
        private AccessHeatmapService accessHeatmapService;

        @MockBean
        private UserSettingsService userSettingsService;

        @MockBean
        private ClientIpUtil clientIpUtil;

        @Autowired
        private ObjectMapper objectMapper;

        @BeforeEach
        void setUpRateLimiter() {
                Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
                Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString())).thenReturn(true);
                Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString())).thenReturn(100);
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testGetProfile_Success() throws Exception {
                UserResponse response = UserResponse.builder()
                        .id(1L)
                        .username("testuser")
                        .email("test@example.com")
                        .build();

                when(userService.getUserProfile("testuser")).thenReturn(response);

                mockMvc.perform(get("/api/users/profile"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.username").value("testuser"))
                        .andExpect(jsonPath("$.email").value("test@example.com"));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testUpdateProfile_Success() throws Exception {
                com.revature.passwordmanager.dto.request.UpdateProfileRequest request = new com.revature.passwordmanager.dto.request.UpdateProfileRequest();
                request.setName("New Name");
                request.setPhoneNumber("1234567890");
                UserResponse response = UserResponse.builder()
                        .id(1L)
                        .username("testuser")
                        .name("New Name")
                        .phoneNumber("1234567890")
                        .build();

                when(userService.updateProfile(ArgumentMatchers.anyString(),
                        any(com.revature.passwordmanager.dto.request.UpdateProfileRequest.class)))
                        .thenReturn(response);

                mockMvc.perform(put("/api/users/profile")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.username").value("testuser"))
                        .andExpect(jsonPath("$.name").value("New Name"))
                        .andExpect(jsonPath("$.phoneNumber").value("1234567890"));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testChangePassword_WithMockUser_ShouldSucceed() throws Exception {
                ChangePasswordRequest request = new ChangePasswordRequest();
                request.setOldPassword("oldPassword");
                request.setNewPassword("newSafePassword123!");

                doNothing().when(userService).changeMasterPassword(ArgumentMatchers.eq("testuser"),
                        ArgumentMatchers.any(ChangePasswordRequest.class));

                mockMvc.perform(put("/api/users/change-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.message")
                                .value("Password changed successfully"));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testDeleteAccount_Success() throws Exception {
                AccountDeletionRequest request = new AccountDeletionRequest();
                request.setMasterPassword("password");
                request.setConfirmation(true);

                doNothing().when(accountDeletionService)
                        .scheduleAccountDeletion(anyString(), any(AccountDeletionRequest.class));

                mockMvc.perform(delete("/api/users/account")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString(
                                "Account scheduled for deletion")));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testCancelDeletion_Success() throws Exception {
                doNothing().when(accountDeletionService).cancelAccountDeletion("testuser");

                mockMvc.perform(post("/api/users/account/cancel-deletion"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.message").value("Account deletion cancelled."));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testGetSecurityQuestions_Success() throws Exception {
                User user = new User();
                user.setUsername("testuser");

                SecurityQuestion sq = new SecurityQuestion();
                sq.setQuestionText("Q1");
                sq.setAnswerHash("hash");

                List<SecurityQuestion> questions = Collections
                        .singletonList(sq);

                Mockito.when(userRepository.findByUsername("testuser"))
                        .thenReturn(Optional.of(user));
                Mockito.when(securityQuestionService.getSecurityQuestions(user)).thenReturn(questions);

                mockMvc
                        .perform(
                                get("/api/users/security-questions"))
                        .andExpect(status().isOk())
                        .andExpect(
                                jsonPath("$[0].question")
                                        .value("Q1"));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testUpdateSecurityQuestions_Success() throws Exception {
                User user = new User();
                user.setUsername("testuser");
                user.setMasterPasswordHash("hashedPassword");

                UpdateSecurityQuestionsRequest request = new UpdateSecurityQuestionsRequest();
                request.setMasterPassword("password");
                SecurityQuestionDTO dto = new SecurityQuestionDTO(
                        "Q1", "A1");
                request.setSecurityQuestions(Arrays.asList(dto, dto, dto));

                Mockito.when(userRepository.findByUsername("testuser"))
                        .thenReturn(Optional.of(user));
                Mockito.when(passwordEncoder.matches("password", "hashedPassword")).thenReturn(true);
                doNothing().when(securityQuestionService).saveSecurityQuestions(ArgumentMatchers.any(),
                        ArgumentMatchers.anyList());

                mockMvc.perform(put("/api/users/security-questions")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testGetActivityHeatmap_Success() throws Exception {
                List<Integer> hourly = Collections.nCopies(24, 0);
                List<Integer> daily = Collections.nCopies(7, 0);

                HeatmapResponse response = HeatmapResponse.builder()
                        .accessByHour(hourly)
                        .accessByDay(daily)
                        .peakHour(14)
                        .peakDay("Wednesday")
                        .totalAccesses(150)
                        .period("LAST_30_DAYS")
                        .build();

                when(accessHeatmapService.getAccessHeatmap("testuser")).thenReturn(response);

                mockMvc.perform(get("/api/users/activity-heatmap"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.peakHour").value(14))
                        .andExpect(jsonPath("$.peakDay").value("Wednesday"))
                        .andExpect(jsonPath("$.totalAccesses").value(150))
                        .andExpect(jsonPath("$.period").value("LAST_30_DAYS"))
                        .andExpect(jsonPath("$.accessByHour").isArray())
                        .andExpect(jsonPath("$.accessByDay").isArray());
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testGetDashboard_Success() throws Exception {
                com.revature.passwordmanager.dto.response.DashboardResponse response = com.revature.passwordmanager.dto.response.DashboardResponse
                        .builder()
                        .totalVaultEntries(10)
                        .totalCategories(5)
                        .totalFolders(3)
                        .totalFavorites(2)
                        .weakPasswordsCount(0)
                        .reusedPasswordsCount(0)
                        .oldPasswordsCount(0)
                        .unreadNotifications(1)
                        .build();

                when(userService.getDashboardData("testuser")).thenReturn(response);

                mockMvc.perform(get("/api/users/dashboard"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalVaultEntries").value(10))
                        .andExpect(jsonPath("$.totalCategories").value(5))
                        .andExpect(jsonPath("$.totalFolders").value(3))
                        .andExpect(jsonPath("$.totalFavorites").value(2))
                        .andExpect(jsonPath("$.weakPasswordsCount").value(0))
                        .andExpect(jsonPath("$.reusedPasswordsCount").value(0))
                        .andExpect(jsonPath("$.oldPasswordsCount").value(0))
                        .andExpect(jsonPath("$.unreadNotifications").value(1));
        }

        @Test
        @WithMockUser(username = "testuser")
        public void testToggleReadOnlyMode_Success() throws Exception {
                com.revature.passwordmanager.dto.request.ToggleReadOnlyRequest request = new com.revature.passwordmanager.dto.request.ToggleReadOnlyRequest();
                request.setReadOnlyMode(true);

                com.revature.passwordmanager.dto.response.UserSettingsResponse response = com.revature.passwordmanager.dto.response.UserSettingsResponse
                        .builder()
                        .theme("SYSTEM")
                        .language("en-US")
                        .autoLogoutMinutes(15)
                        .readOnlyMode(true)
                        .build();

                when(userSettingsService.toggleReadOnlyMode("testuser", true)).thenReturn(response);

                mockMvc.perform(put("/api/users/read-only-mode")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.theme").value("SYSTEM"))
                        .andExpect(jsonPath("$.language").value("en-US"))
                        .andExpect(jsonPath("$.autoLogoutMinutes").value(15))
                        .andExpect(jsonPath("$.readOnlyMode").value(true));
        }
}
