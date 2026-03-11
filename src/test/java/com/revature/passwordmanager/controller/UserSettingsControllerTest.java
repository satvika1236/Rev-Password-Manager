package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.dto.request.UserSettingsRequest;
import com.revature.passwordmanager.dto.response.UserSettingsResponse;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.RateLimitService;
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
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = UserSettingsController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class
})
class UserSettingsControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private UserSettingsService userSettingsService;

        @Autowired
        private ObjectMapper objectMapper;

        // Mock security beans
        @MockBean
        private JwtTokenProvider jwtTokenProvider;
        @MockBean
        private UserDetailsService userDetailsService;
        @MockBean
        private SessionService sessionService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private ClientIpUtil clientIpUtil;

        private UserSettingsResponse response;
        private UserSettingsRequest request;

        @BeforeEach
        void setUp() {
                Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
                Mockito.when(
                                rateLimitService.isAllowed(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
                        .thenReturn(true);
                Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString())).thenReturn(100);

                response = UserSettingsResponse.builder()
                        .theme("SYSTEM")
                        .language("en-US")
                        .autoLogoutMinutes(15)
                        .build();

                request = UserSettingsRequest.builder()
                        .theme("DARK")
                        .build();
        }

        @Test
        @WithMockUser(username = "testuser")
        void getSettings_ShouldReturnOk() throws Exception {
                when(userSettingsService.getSettings("testuser")).thenReturn(response);

                mockMvc.perform(get("/api/settings"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.theme").value("SYSTEM"))
                        .andExpect(jsonPath("$.language").value("en-US"))
                        .andExpect(jsonPath("$.autoLogoutMinutes").value(15));
        }

        @Test
        @WithMockUser(username = "testuser")
        void updateSettings_ShouldReturnOk() throws Exception {
                when(userSettingsService.updateSettings(eq("testuser"), any(UserSettingsRequest.class)))
                        .thenReturn(response);

                mockMvc.perform(put("/api/settings")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.theme").value("SYSTEM"))
                        .andExpect(jsonPath("$.language").value("en-US"))
                        .andExpect(jsonPath("$.autoLogoutMinutes").value(15));
        }
}
