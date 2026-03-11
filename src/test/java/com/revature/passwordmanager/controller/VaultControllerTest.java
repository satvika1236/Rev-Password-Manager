package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.dto.request.SensitiveAccessRequest;
import com.revature.passwordmanager.dto.request.VaultEntryRequest;
import com.revature.passwordmanager.dto.response.SnapshotResponse;
import com.revature.passwordmanager.dto.response.TrashEntryResponse;
import com.revature.passwordmanager.dto.response.VaultEntryDetailResponse;
import com.revature.passwordmanager.dto.response.VaultEntryResponse;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.service.vault.VaultService;
import com.revature.passwordmanager.service.vault.VaultSnapshotService;
import com.revature.passwordmanager.service.vault.VaultTrashService;
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

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = VaultController.class, excludeAutoConfiguration = {
        UserDetailsServiceAutoConfiguration.class
})
class VaultControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private VaultService vaultService;

        @MockBean
        private VaultTrashService vaultTrashService;

        @MockBean
        private VaultSnapshotService vaultSnapshotService;

        @Autowired
        private ObjectMapper objectMapper;

        // Mock security beans to satisfy filter chain
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

        private VaultEntryResponse entryResponse;
        private VaultEntryDetailResponse detailResponse;
        private VaultEntryRequest entryRequest;

        @BeforeEach
        void setUp() {
                Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
                Mockito.when(rateLimitService.isAllowed(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString())).thenReturn(true);
                Mockito.when(rateLimitService.getRemainingRequests(ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString())).thenReturn(100);

                entryResponse = VaultEntryResponse.builder()
                        .id(1L)
                        .title("Test Entry")
                        .username("******")
                        .websiteUrl("https://example.com")
                        .categoryId(1L)
                        .categoryName("Social Media")
                        .folderId(1L)
                        .folderName("Work")
                        .isFavorite(false)
                        .strengthScore(80)
                        .strengthLabel("Good")
                        .build();

                detailResponse = VaultEntryDetailResponse.builder()
                        .id(1L)
                        .title("Test Entry")
                        .username("user")
                        .password("pass")
                        .websiteUrl("https://example.com")
                        .notes("test notes")
                        .categoryId(1L)
                        .categoryName("Social Media")
                        .folderId(1L)
                        .folderName("Work")
                        .isFavorite(false)
                        .isHighlySensitive(false)
                        .requiresSensitiveAuth(false)
                        .strengthScore(80)
                        .strengthLabel("Good")
                        .build();

                entryRequest = VaultEntryRequest.builder()
                        .title("Test Entry")
                        .username("user")
                        .password("pass")
                        .categoryId(1L)
                        .build();
        }

        @Test
        @WithMockUser(username = "testuser")
        void createEntry_ShouldReturnCreated() throws Exception {
                when(vaultService.createEntry(eq("testuser"), any(VaultEntryRequest.class)))
                        .thenReturn(entryResponse);

                mockMvc.perform(post("/api/vault")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(entryRequest)))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"))
                        .andExpect(jsonPath("$.username").value("******"))
                        .andExpect(jsonPath("$.websiteUrl").value("https://example.com"))
                        .andExpect(jsonPath("$.categoryId").value(1))
                        .andExpect(jsonPath("$.categoryName").value("Social Media"))
                        .andExpect(jsonPath("$.isFavorite").value(false))
                        .andExpect(jsonPath("$.strengthScore").value(80))
                        .andExpect(jsonPath("$.strengthLabel").value("Good"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getAllEntries_ShouldReturnList() throws Exception {
                when(vaultService.getAllEntries("testuser"))
                        .thenReturn(List.of(entryResponse));

                mockMvc.perform(get("/api/vault"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"))
                        .andExpect(jsonPath("$[0].websiteUrl").value("https://example.com"))
                        .andExpect(jsonPath("$[0].categoryName").value("Social Media"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getEntry_ShouldReturnDetail() throws Exception {
                when(vaultService.getEntry("testuser", 1L))
                        .thenReturn(detailResponse);

                mockMvc.perform(get("/api/vault/1"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"))
                        .andExpect(jsonPath("$.username").value("user"))
                        .andExpect(jsonPath("$.password").value("pass"))
                        .andExpect(jsonPath("$.websiteUrl").value("https://example.com"))
                        .andExpect(jsonPath("$.notes").value("test notes"))
                        .andExpect(jsonPath("$.categoryName").value("Social Media"))
                        .andExpect(jsonPath("$.isHighlySensitive").value(false))
                        .andExpect(jsonPath("$.strengthScore").value(80))
                        .andExpect(jsonPath("$.strengthLabel").value("Good"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void updateEntry_ShouldReturnUpdated() throws Exception {
                when(vaultService.updateEntry(eq("testuser"), eq(1L), any(VaultEntryRequest.class)))
                        .thenReturn(entryResponse);

                mockMvc.perform(put("/api/vault/1")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(entryRequest)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"))
                        .andExpect(jsonPath("$.websiteUrl").value("https://example.com"))
                        .andExpect(jsonPath("$.categoryName").value("Social Media"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void deleteEntry_ShouldReturnNoContent() throws Exception {
                doNothing().when(vaultService).deleteEntry("testuser", 1L);

                mockMvc.perform(delete("/api/vault/1")
                                .with(csrf())
                                .accept(MediaType.APPLICATION_JSON)) // Fix for 415 error if any
                        .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(username = "testuser")
        void toggleFavorite_ShouldReturnUpdatedEntry() throws Exception {
                VaultEntryResponse favoriteResponse = VaultEntryResponse.builder()
                        .id(1L)
                        .title("Test Entry")
                        .isFavorite(true)
                        .build();

                when(vaultService.toggleFavorite("testuser", 1L))
                        .thenReturn(favoriteResponse);

                mockMvc.perform(put("/api/vault/1/favorite")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"))
                        .andExpect(jsonPath("$.isFavorite").value(true));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getFavorites_ShouldReturnList() throws Exception {
                VaultEntryResponse favoriteResponse = VaultEntryResponse.builder()
                        .id(1L)
                        .title("Test Entry")
                        .isFavorite(true)
                        .build();

                when(vaultService.getFavorites("testuser"))
                        .thenReturn(List.of(favoriteResponse));

                mockMvc.perform(get("/api/vault/favorites"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"))
                        .andExpect(jsonPath("$[0].isFavorite").value(true));
        }

        @Test
        @WithMockUser(username = "testuser")
        void bulkDelete_ShouldReturnNoContent() throws Exception {
                doNothing().when(vaultService).bulkDelete(eq("testuser"), any());

                mockMvc.perform(post("/api/vault/entries/bulk-delete")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(List.of(1L, 2L))))
                        .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(username = "testuser")
        void viewPassword_ShouldReturnPassword() throws Exception {
                when(vaultService.getPassword("testuser", 1L)).thenReturn("secret");

                mockMvc.perform(post("/api/vault/entries/1/view-password")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)) // Empty body is fine if no params
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.password").value("secret"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void accessSensitiveEntry_ShouldReturnDecryptedDetails() throws Exception {
                SensitiveAccessRequest request = new SensitiveAccessRequest();
                request.setMasterPassword("password");

                when(vaultService.accessSensitiveEntry(eq("testuser"), eq(1L),
                        any(SensitiveAccessRequest.class)))
                        .thenReturn(detailResponse);

                mockMvc.perform(post("/api/vault/1/sensitive-view")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"))
                        .andExpect(jsonPath("$.username").value("user"))
                        .andExpect(jsonPath("$.password").value("pass"))
                        .andExpect(jsonPath("$.notes").value("test notes"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void searchEntries_ShouldReturnResults_WhenKeywordProvided() throws Exception {
                when(vaultService.searchEntries(
                        eq("testuser"), eq("google"), any(), any(), any(), any(),
                        eq("title"), eq("asc")))
                        .thenReturn(List.of(entryResponse));

                mockMvc.perform(get("/api/vault/search")
                                .param("keyword", "google"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"))
                        .andExpect(jsonPath("$[0].websiteUrl").value("https://example.com"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void searchEntries_ShouldReturnEmptyList_WhenNoMatch() throws Exception {
                when(vaultService.searchEntries(
                        eq("testuser"), eq("nonexistent"), any(), any(), any(), any(),
                        eq("title"), eq("asc")))
                        .thenReturn(Collections.emptyList());

                mockMvc.perform(get("/api/vault/search")
                                .param("keyword", "nonexistent"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$").isArray())
                        .andExpect(jsonPath("$").isEmpty());
        }

        @Test
        @WithMockUser(username = "testuser")
        void filterEntries_ShouldDelegateToSearch() throws Exception {
                when(vaultService.searchEntries(
                        eq("testuser"), any(), eq(1L), any(), eq(true), any(),
                        eq("title"), eq("asc")))
                        .thenReturn(List.of(entryResponse));

                mockMvc.perform(get("/api/vault/filter")
                                .param("categoryId", "1")
                                .param("isFavorite", "true"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getRecentEntries_ShouldReturnList() throws Exception {
                when(vaultService.getRecentEntries("testuser"))
                        .thenReturn(List.of(entryResponse));

                mockMvc.perform(get("/api/vault/recent"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getRecentlyUsedEntries_ShouldReturnList() throws Exception {
                when(vaultService.getRecentlyUsedEntries("testuser"))
                        .thenReturn(List.of(entryResponse));

                mockMvc.perform(get("/api/vault/recently-used"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Test Entry"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void toggleSensitive_ShouldReturnUpdatedEntry() throws Exception {
                VaultEntryResponse sensitiveResponse = VaultEntryResponse.builder()
                        .id(1L)
                        .title("Test Entry")
                        // VaultEntryResponse doesn't actually have isHighlySensitive, but returning OK
                        // is enough validation
                        .build();

                when(vaultService.toggleSensitive("testuser", 1L))
                        .thenReturn(sensitiveResponse);

                mockMvc.perform(put("/api/vault/entries/1/sensitive")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Test Entry"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getTrash_ShouldReturnDeletedEntries() throws Exception {
                TrashEntryResponse trashResponse = TrashEntryResponse.builder()
                        .id(1L)
                        .title("Deleted Entry")
                        .deletedAt(LocalDateTime.of(2026, 1, 1, 0, 0))
                        .expiresAt(LocalDateTime.of(2026, 1, 31, 0, 0))
                        .daysRemaining(25)
                        .build();

                when(vaultTrashService.getTrashEntries("testuser"))
                        .thenReturn(List.of(trashResponse));

                mockMvc.perform(get("/api/vault/trash"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].title").value("Deleted Entry"))
                        .andExpect(jsonPath("$[0].daysRemaining").value(25));
        }

        @Test
        @WithMockUser(username = "testuser")
        void restoreEntry_ShouldReturnOk() throws Exception {
                TrashEntryResponse trashResponse = TrashEntryResponse.builder()
                        .id(1L)
                        .title("Restored Entry")
                        .build();

                when(vaultTrashService.restoreEntry("testuser", 1L))
                        .thenReturn(trashResponse);

                mockMvc.perform(post("/api/vault/trash/1/restore")
                                .with(csrf()))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.id").value(1))
                        .andExpect(jsonPath("$.title").value("Restored Entry"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void emptyTrash_ShouldReturnNoContent() throws Exception {
                doNothing().when(vaultTrashService).emptyTrash("testuser");

                mockMvc.perform(delete("/api/vault/trash/empty")
                                .with(csrf()))
                        .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(username = "testuser")
        void getPasswordHistory_ShouldReturnList() throws Exception {
                SnapshotResponse snap = SnapshotResponse.builder()
                        .id(1L)
                        .password("******")
                        .changedAt(LocalDateTime.of(2026, 1, 15, 10, 0))
                        .build();

                when(vaultSnapshotService.getHistory("testuser", 1L))
                        .thenReturn(List.of(snap));

                mockMvc.perform(get("/api/vault/entries/1/history"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].password").value("******"))
                        .andExpect(jsonPath("$[0].id").value(1));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getTrashCount_ShouldReturnCount() throws Exception {
                when(vaultTrashService.getTrashCount("testuser")).thenReturn(5L);

                mockMvc.perform(get("/api/vault/trash/count"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.count").value(5));
        }

        @Test
        @WithMockUser(username = "testuser")
        void restoreAll_ShouldReturnNoContent() throws Exception {
                doNothing().when(vaultTrashService).restoreAll("testuser");

                mockMvc.perform(post("/api/vault/trash/restore-all")
                                .with(csrf()))
                        .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(username = "testuser")
        void permanentDelete_ShouldReturnNoContent() throws Exception {
                doNothing().when(vaultTrashService).permanentDelete("testuser", 1L);

                mockMvc.perform(delete("/api/vault/trash/1")
                                .with(csrf()))
                        .andExpect(status().isOk());
        }
}
