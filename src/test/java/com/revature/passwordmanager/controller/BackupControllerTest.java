package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.request.ImportRequest;
import com.revature.passwordmanager.dto.request.ThirdPartyImportRequest;
import com.revature.passwordmanager.dto.response.ExportResponse;
import com.revature.passwordmanager.dto.response.ImportResult;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.backup.ExportService;
import com.revature.passwordmanager.service.backup.ImportService;
import com.revature.passwordmanager.service.backup.ThirdPartyImportService;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.util.ClientIpUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = BackupController.class, excludeAutoConfiguration = {
        org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class
})
@Import(SecurityConfig.class)
public class BackupControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @MockBean
        private ExportService exportService;

        @MockBean
        private ImportService importService;

        @MockBean
        private ThirdPartyImportService thirdPartyImportService;

        @MockBean
        private CustomUserDetailsService customUserDetailsService;

        @MockBean
        private JwtTokenProvider jwtTokenProvider;

        @MockBean
        private SessionService sessionService;

        @MockBean
        private com.revature.passwordmanager.service.vault.VaultSnapshotService vaultSnapshotService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private ClientIpUtil clientIpUtil;

        @BeforeEach
        void setUp() {
                Mockito.when(clientIpUtil.getClientIpAddress(ArgumentMatchers.any())).thenReturn("127.0.0.1");
                when(rateLimitService.isAllowed(anyString(), anyString())).thenReturn(true);
                when(rateLimitService.getRemainingRequests(anyString(), anyString())).thenReturn(100);
        }

        @Test
        @WithMockUser(username = "testuser")
        void exportVault_ShouldReturnExportResponse() throws Exception {
                ExportResponse response = ExportResponse.builder()
                        .fileName("vault_export.json")
                        .format("JSON")
                        .entryCount(5)
                        .encrypted(false)
                        .data("{\"entries\":[]}")
                        .exportedAt(LocalDateTime.now())
                        .build();

                when(exportService.exportVault("testuser", "JSON", null)).thenReturn(response);

                mockMvc.perform(get("/api/backup/export")
                                .param("format", "JSON"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.fileName").value("vault_export.json"))
                        .andExpect(jsonPath("$.format").value("JSON"))
                        .andExpect(jsonPath("$.entryCount").value(5))
                        .andExpect(jsonPath("$.encrypted").value(false))
                        .andExpect(jsonPath("$.data").value("{\"entries\":[]}"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void exportVault_DefaultFormat_ShouldReturnExportResponse() throws Exception {
                ExportResponse response = ExportResponse.builder()
                        .fileName("vault_export.json")
                        .format("JSON")
                        .entryCount(3)
                        .encrypted(false)
                        .data("{}")
                        .exportedAt(LocalDateTime.now())
                        .build();

                when(exportService.exportVault("testuser", "JSON", null)).thenReturn(response);

                mockMvc.perform(get("/api/backup/export"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.format").value("JSON"))
                        .andExpect(jsonPath("$.fileName").value("vault_export.json"))
                        .andExpect(jsonPath("$.entryCount").value(3))
                        .andExpect(jsonPath("$.encrypted").value(false));
        }

        @Test
        @WithMockUser(username = "testuser")
        void importVault_ShouldReturnImportResult() throws Exception {
                ImportRequest request = ImportRequest.builder()
                        .data("{\"entries\":[]}")
                        .format("JSON")
                        .build();

                ImportResult result = ImportResult.builder()
                        .totalProcessed(10)
                        .successCount(8)
                        .failCount(2)
                        .message("Import completed")
                        .build();

                when(importService.importVault(anyString(), any(ImportRequest.class))).thenReturn(result);

                mockMvc.perform(post("/api/backup/import")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalProcessed").value(10))
                        .andExpect(jsonPath("$.successCount").value(8))
                        .andExpect(jsonPath("$.failCount").value(2))
                        .andExpect(jsonPath("$.message").value("Import completed"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void importFromExternal_ShouldReturnImportResult() throws Exception {
                ThirdPartyImportRequest request = ThirdPartyImportRequest.builder()
                        .source("LastPass")
                        .data("csv-data-here")
                        .build();

                ImportResult result = ImportResult.builder()
                        .totalProcessed(15)
                        .successCount(15)
                        .failCount(0)
                        .message("External import completed successfully")
                        .build();

                when(thirdPartyImportService.importFromThirdParty(anyString(), any(ThirdPartyImportRequest.class)))
                        .thenReturn(result);

                mockMvc.perform(post("/api/backup/import-external")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalProcessed").value(15))
                        .andExpect(jsonPath("$.successCount").value(15))
                        .andExpect(jsonPath("$.failCount").value(0))
                        .andExpect(jsonPath("$.message").value("External import completed successfully"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void previewExport_ShouldReturnExportResponse() throws Exception {
                ExportResponse response = ExportResponse.builder()
                        .fileName("preview.json")
                        .format("JSON")
                        .entryCount(3)
                        .encrypted(false)
                        .data("{\"preview\":true}")
                        .exportedAt(LocalDateTime.now())
                        .build();

                when(exportService.previewExport("testuser", "JSON")).thenReturn(response);

                mockMvc.perform(get("/api/backup/export/preview")
                                .param("format", "JSON"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.fileName").value("preview.json"))
                        .andExpect(jsonPath("$.format").value("JSON"))
                        .andExpect(jsonPath("$.entryCount").value(3))
                        .andExpect(jsonPath("$.encrypted").value(false))
                        .andExpect(jsonPath("$.data").value("{\"preview\":true}"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void validateImport_ShouldReturnImportResult() throws Exception {
                ImportRequest request = new ImportRequest();
                request.setFormat("JSON");
                request.setData("data");

                ImportResult result = ImportResult.builder().totalProcessed(5).successCount(5).failCount(0)
                        .message("Validation passed").build();
                when(importService.validateImport(anyString(), any(ImportRequest.class))).thenReturn(result);

                mockMvc.perform(post("/api/backup/import/validate")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.totalProcessed").value(5))
                        .andExpect(jsonPath("$.successCount").value(5))
                        .andExpect(jsonPath("$.failCount").value(0))
                        .andExpect(jsonPath("$.message").value("Validation passed"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getSupportedFormats_ShouldReturnList() throws Exception {
                when(thirdPartyImportService.getSupportedFormats())
                        .thenReturn(java.util.List.of("BITWARDEN", "LASTPASS"));

                mockMvc.perform(get("/api/backup/import-external/formats"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0]").value("BITWARDEN"))
                        .andExpect(jsonPath("$[1]").value("LASTPASS"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void getAllSnapshots_ShouldReturnList() throws Exception {
                com.revature.passwordmanager.dto.response.SnapshotResponse snap = com.revature.passwordmanager.dto.response.SnapshotResponse
                        .builder().id(1L).password("******").changedAt(LocalDateTime.now()).build();
                when(vaultSnapshotService.getAllSnapshots("testuser")).thenReturn(java.util.List.of(snap));

                mockMvc.perform(get("/api/backup/snapshots"))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].id").value(1))
                        .andExpect(jsonPath("$[0].password").value("******"));
        }

        @Test
        @WithMockUser(username = "testuser")
        void restoreSnapshot_ShouldReturnOk() throws Exception {
                mockMvc.perform(post("/api/backup/snapshots/1/restore"))
                        .andExpect(status().isOk());
        }

        @Test
        void export_WithoutAuth_ShouldReturnForbidden() throws Exception {
                mockMvc.perform(get("/api/backup/export"))
                        .andExpect(status().isForbidden());
        }
}
