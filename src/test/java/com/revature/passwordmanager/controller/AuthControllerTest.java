package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.dto.request.LoginRequest;
import com.revature.passwordmanager.dto.request.RecoveryRequest;
import com.revature.passwordmanager.dto.request.RefreshTokenRequest;
import com.revature.passwordmanager.dto.request.RegistrationRequest;
import com.revature.passwordmanager.dto.response.AuthResponse;
import com.revature.passwordmanager.dto.response.UserResponse;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtAuthenticationFilter;
import com.revature.passwordmanager.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.revature.passwordmanager.service.auth.AccountRecoveryService;
import com.revature.passwordmanager.service.auth.AuthenticationService;
import com.revature.passwordmanager.service.auth.RegistrationService;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.DuressService;
import com.revature.passwordmanager.service.security.RateLimitService;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class, excludeAutoConfiguration = {
                UserDetailsServiceAutoConfiguration.class
})
@Import({ SecurityConfig.class, JwtAuthenticationFilter.class,
                com.revature.passwordmanager.security.RateLimitFilter.class })
class AuthControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private RegistrationService registrationService;

        @MockBean
        private AuthenticationService authenticationService;

        @MockBean
        private JwtTokenProvider jwtTokenProvider;

        @MockBean
        private SessionService sessionService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private CustomUserDetailsService customUserDetailsService;

        @MockBean
        private AccountRecoveryService accountRecoveryService;

        @MockBean
        private DuressService duressService;

        @MockBean
        private UserRepository userRepository;

        @MockBean
        private com.revature.passwordmanager.service.security.CaptchaService captchaService;

        @MockBean
        private PasswordEncoder passwordEncoder;

        @MockBean
        private com.revature.passwordmanager.util.ClientIpUtil clientIpUtil;

        @Autowired
        private ObjectMapper objectMapper;

        @BeforeEach
        void setUp() {
                Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any()))
                                .thenReturn("127.0.0.1");
                Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.any(),
                                ArgumentMatchers.any())).thenReturn(true);
                Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.any(),
                                ArgumentMatchers.any())).thenReturn(100);
        }

        @Test
        @WithMockUser
        void testRegister() throws Exception {
                RegistrationRequest request = new RegistrationRequest();
                request.setUsername("testuser");
                request.setEmail("test@example.com");
                request.setMasterPassword("password123!");

                SecurityQuestionDTO q1 = new SecurityQuestionDTO(
                                "Q", "A");
                request.setSecurityQuestions(Arrays.asList(q1, q1, q1));

                UserResponse response = UserResponse.builder()
                                .id(1L)
                                .username("testuser")
                                .email("test@example.com")
                                .name("Test User")
                                .phoneNumber("1234567890")
                                .is2faEnabled(false)
                                .build();
                when(registrationService.registerUser(any(RegistrationRequest.class))).thenReturn(response);

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.email").value("test@example.com"))
                                .andExpect(jsonPath("$.name").value("Test User"))
                                .andExpect(jsonPath("$.phoneNumber").value("1234567890"));
        }

        @Test
        @WithMockUser
        void testLogin() throws Exception {
                LoginRequest request = new LoginRequest();
                request.setUsername("testuser");
                request.setMasterPassword("password");

                AuthResponse response = AuthResponse.builder()
                                .accessToken("token")
                                .refreshToken("refresh-token")
                                .tokenType("Bearer")
                                .username("testuser")
                                .expiresIn(3600)
                                .requires2FA(false)
                                .message("Login successful")
                                .build();
                when(authenticationService.login(any(LoginRequest.class), any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").value("token"))
                                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.expiresIn").value(3600))
                                .andExpect(jsonPath("$.requires2FA").value(false))
                                .andExpect(jsonPath("$.message").value("Login successful"));
        }

        @Test
        @WithMockUser
        void testRefreshToken() throws Exception {
                RefreshTokenRequest request = new RefreshTokenRequest();
                request.setRefreshToken("valid-refresh-token");

                AuthResponse response = AuthResponse.builder()
                                .accessToken("new-access-token")
                                .refreshToken("new-refresh-token")
                                .tokenType("Bearer")
                                .username("testuser")
                                .expiresIn(3600)
                                .build();
                when(authenticationService.refreshToken(any(RefreshTokenRequest.class), any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/refresh-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"))
                                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.expiresIn").value(3600));
        }

        @Test
        @WithMockUser(username = "testuser")
        void testLogout() throws Exception {
                doNothing().when(authenticationService).logout(anyString(), anyString());

                mockMvc.perform(post("/api/auth/logout")
                                .header("Authorization", "Bearer test-token"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Logged out successfully"));
        }

        @Test
        @WithMockUser
        void testGetSecurityQuestions() throws Exception {
                when(authenticationService.getSecurityQuestions("testuser"))
                                .thenReturn(Arrays.asList(
                                                new SecurityQuestionDTO("What is your pet?", ""),
                                                new SecurityQuestionDTO("What is your city?", "")));

                mockMvc.perform(get("/api/auth/security-questions/testuser"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$").isArray())
                                .andExpect(jsonPath("$.length()").value(2))
                                .andExpect(jsonPath("$[0].question").value("What is your pet?"))
                                .andExpect(jsonPath("$[0].answer").value(""))
                                .andExpect(jsonPath("$[1].question").value("What is your city?"))
                                .andExpect(jsonPath("$[1].answer").value(""));
        }

        @Test
        @WithMockUser
        void testResetPassword() throws Exception {
                RecoveryRequest request = new RecoveryRequest();
                request.setUsername("testuser");
                request.setNewMasterPassword("newPassword123!");
                // Security answers validation usually happens in Service, but List size
                // validation in DTO
                // DTO requires exactly 3 answers.
                SecurityQuestionDTO q1 = new SecurityQuestionDTO(
                                "Q", "A");
                request.setSecurityAnswers(Arrays.asList(q1, q1, q1));

                doNothing().when(accountRecoveryService)
                                .resetPassword(any(RecoveryRequest.class));

                mockMvc.perform(post("/api/auth/reset-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message")
                                                .value("Password changed successfully"));
        }

        @Test
        @WithMockUser
        void testVerifyOtp() throws Exception {
                AuthResponse response = AuthResponse.builder()
                                .accessToken("otp-verified-token")
                                .refreshToken("otp-refresh-token")
                                .tokenType("Bearer")
                                .username("testuser")
                                .expiresIn(3600)
                                .build();
                when(authenticationService.verifyOtp(anyString(), anyString(), any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/verify-otp")
                                .param("username", "testuser")
                                .param("code", "123456"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").value("otp-verified-token"))
                                .andExpect(jsonPath("$.refreshToken").value("otp-refresh-token"))
                                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.expiresIn").value(3600));
        }

        @Test
        @WithMockUser
        void testSendOtp() throws Exception {
                doNothing().when(authenticationService).sendOtp("testuser");

                mockMvc.perform(post("/api/auth/send-otp")
                                .param("username", "testuser"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message")
                                                .value("OTP sent to your email."));
        }

        @Test
        @WithMockUser
        void testDuressLogin_Success() throws Exception {
                LoginRequest request = new LoginRequest();
                request.setUsername("testuser");
                request.setMasterPassword("duressPassword");

                AuthResponse response = AuthResponse.builder()
                                .accessToken("duressToken")
                                .refreshToken("duress-refresh")
                                .tokenType("Bearer")
                                .username("testuser")
                                .expiresIn(3600)
                                .build();
                when(authenticationService.duressLogin(any(LoginRequest.class), any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/duress-login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").value("duressToken"))
                                .andExpect(jsonPath("$.refreshToken").value("duress-refresh"))
                                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.expiresIn").value(3600));
        }

        @Test
        @WithMockUser
        void testDuressLogin_Unauthorized() throws Exception {
                LoginRequest request = new LoginRequest();
                request.setUsername("testuser");
                request.setMasterPassword("wrongPassword");

                when(authenticationService.duressLogin(any(LoginRequest.class), any()))
                                .thenThrow(new com.revature.passwordmanager.exception.AuthenticationException(
                                                "Invalid username or password"));

                mockMvc.perform(post("/api/auth/duress-login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @WithMockUser(username = "testuser")
        void testSetDuressPassword() throws Exception {
                doNothing().when(duressService).setDuressPassword(anyString(), anyString());

                com.revature.passwordmanager.dto.request.SetDuressPasswordRequest request = new com.revature.passwordmanager.dto.request.SetDuressPasswordRequest(
                                "myDuressPass");

                mockMvc.perform(post("/api/auth/set-duress-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Duress password set successfully"));
        }

        @Test
        @WithMockUser
        void testGetPasswordHint() throws Exception {
                User user = new User();
                user.setUsername("testuser");
                user.setPasswordHint("My first pet");

                when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

                mockMvc.perform(get("/api/auth/password-hint/testuser"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.hint").value("My first pet"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void testSetPasswordHint_Success() throws Exception {
                User user = new User();
                user.setUsername("testuser");
                user.setMasterPasswordHash("hashedPassword");

                when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
                when(passwordEncoder.matches("masterPassword123", "hashedPassword")).thenReturn(true);
                when(userRepository.save(any(User.class))).thenReturn(user);

                com.revature.passwordmanager.dto.request.SetPasswordHintRequest request = new com.revature.passwordmanager.dto.request.SetPasswordHintRequest(
                                "masterPassword123", "My first pet");

                mockMvc.perform(put("/api/auth/password-hint")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Password hint updated"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void testSetPasswordHint_NoMasterPassword() throws Exception {
                User user = new User();
                user.setUsername("testuser");

                when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

                com.revature.passwordmanager.dto.request.SetPasswordHintRequest request = new com.revature.passwordmanager.dto.request.SetPasswordHintRequest(
                                "", "My first pet");

                mockMvc.perform(put("/api/auth/password-hint")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser(username = "testuser")
        void testSetPasswordHint_HintContainsPassword() throws Exception {
                User user = new User();
                user.setUsername("testuser");
                user.setMasterPasswordHash("hashedPassword");

                when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
                when(passwordEncoder.matches("masterPassword123", "hashedPassword")).thenReturn(true);

                com.revature.passwordmanager.dto.request.SetPasswordHintRequest request = new com.revature.passwordmanager.dto.request.SetPasswordHintRequest(
                                "masterPassword123", "My MasterPassword123 is terrible");

                mockMvc.perform(put("/api/auth/password-hint")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message")
                                                .value("Password hint cannot contain the master password"));
        }

        @Test
        @WithMockUser
        void testForgotPassword() throws Exception {
                com.revature.passwordmanager.dto.request.ForgotPasswordRequest request = new com.revature.passwordmanager.dto.request.ForgotPasswordRequest();
                request.setUsername("testuser");

                doNothing().when(accountRecoveryService).forgotPassword(any());

                mockMvc.perform(post("/api/auth/forgot-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value(
                                                "If the account exists, password recovery has been initiated."));
        }

        @Test
        @WithMockUser
        void testVerifySecurityQuestions() throws Exception {
                com.revature.passwordmanager.dto.request.VerifySecurityQuestionsRequest request = new com.revature.passwordmanager.dto.request.VerifySecurityQuestionsRequest();
                request.setUsername("testuser");
                SecurityQuestionDTO q1 = new SecurityQuestionDTO("Q", "A");
                request.setSecurityAnswers(Arrays.asList(q1, q1, q1));

                doNothing().when(accountRecoveryService).verifySecurityQuestions(any());

                mockMvc.perform(post("/api/auth/verify-security-questions")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Security questions verified successfully"));
        }

        @Test
        @WithMockUser
        void testVerifyCaptcha_Success() throws Exception {
                com.revature.passwordmanager.dto.request.VerifyCaptchaRequest request = new com.revature.passwordmanager.dto.request.VerifyCaptchaRequest();
                request.setCaptchaToken("valid-token");

                when(captchaService.verifyCaptcha("valid-token")).thenReturn(true);

                mockMvc.perform(post("/api/auth/verify-captcha")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("CAPTCHA verified successfully"));
        }

        @Test
        @WithMockUser
        void testValidateToken_Valid() throws Exception {
                when(authenticationService.validateToken("valid-token")).thenReturn(true);

                mockMvc.perform(get("/api/auth/validate-token")
                                .header("Authorization", "Bearer valid-token"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(true));
        }

        @Test
        @WithMockUser(username = "testuser")
        void testVerifyMasterPassword() throws Exception {
                com.revature.passwordmanager.dto.request.VerifyMasterPasswordRequest request = new com.revature.passwordmanager.dto.request.VerifyMasterPasswordRequest();
                request.setMasterPassword("password123");

                doNothing().when(authenticationService).verifyMasterPassword(anyString(), any());

                mockMvc.perform(post("/api/auth/verify-master-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Master password verified successfully"));
        }

        @Test
        @WithMockUser
        void testResendOtp() throws Exception {
                doNothing().when(authenticationService).sendOtp("testuser");

                mockMvc.perform(post("/api/auth/resend-otp")
                                .param("username", "testuser"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("OTP resent to your email."));
        }

        @Test
        @WithMockUser
        void testVerifyEmail() throws Exception {
                doNothing().when(registrationService).verifyEmail("testuser", "123456");

                mockMvc.perform(post("/api/auth/verify-email")
                                .param("username", "testuser")
                                .param("code", "123456"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message")
                                                .value("Email verified successfully. You can now log in."));
        }

        @Test
        @WithMockUser
        void testResendVerificationOtp() throws Exception {
                doNothing().when(registrationService).resendVerificationOtp("testuser");

                mockMvc.perform(post("/api/auth/resend-verification-otp")
                                .param("username", "testuser"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Verification code resent to your email."));
        }
}
