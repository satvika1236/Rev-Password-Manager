package com.revature.passwordmanager.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.revature.passwordmanager.config.SecurityConfig;
import com.revature.passwordmanager.dto.CategoryDTO;
import com.revature.passwordmanager.dto.request.CreateCategoryRequest;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.security.CustomUserDetailsService;
import com.revature.passwordmanager.security.JwtTokenProvider;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.service.vault.CategoryService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import com.revature.passwordmanager.service.security.RateLimitService;
import com.revature.passwordmanager.dto.response.VaultEntryResponse;
import com.revature.passwordmanager.service.vault.VaultService;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = CategoryController.class, excludeAutoConfiguration = {
                org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class
})
@Import({ SecurityConfig.class, com.revature.passwordmanager.security.JwtAuthenticationFilter.class,
                com.revature.passwordmanager.security.RateLimitFilter.class })
class CategoryControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @MockBean
        private CategoryService categoryService;

        @MockBean
        private VaultService vaultService;

        @MockBean
        private JwtTokenProvider jwtTokenProvider;

        @MockBean
        private CustomUserDetailsService customUserDetailsService;

        @MockBean
        private SessionService sessionService;

        @MockBean
        private RateLimitService rateLimitService;

        @MockBean
        private com.revature.passwordmanager.util.ClientIpUtil clientIpUtil;

        private CategoryDTO userCategoryDTO;
        private CategoryDTO defaultCategoryDTO;
        private CreateCategoryRequest createRequest;

        @BeforeEach
        void setUp() {
                org.mockito.Mockito.when(clientIpUtil.getClientIpAddress(org.mockito.ArgumentMatchers.any()))
                                .thenReturn("127.0.0.1");
                org.mockito.Mockito.when(
                                rateLimitService.isAllowed(org.mockito.ArgumentMatchers.anyString(),
                                                org.mockito.ArgumentMatchers.anyString()))
                                .thenReturn(true);
                org.mockito.Mockito.when(rateLimitService.getRemainingRequests(org.mockito.ArgumentMatchers.anyString(),
                                org.mockito.ArgumentMatchers.anyString())).thenReturn(100);

                userCategoryDTO = CategoryDTO.builder()
                                .id(1L)
                                .name("My Custom Category")
                                .icon("custom-icon")
                                .isDefault(false)
                                .createdAt(LocalDateTime.now())
                                .entryCount(5)
                                .build();

                defaultCategoryDTO = CategoryDTO.builder()
                                .id(100L)
                                .name("Social Media")
                                .icon("social-icon")
                                .isDefault(true)
                                .createdAt(LocalDateTime.now())
                                .entryCount(10)
                                .build();

                createRequest = CreateCategoryRequest.builder()
                                .name("New Category")
                                .icon("new-icon")
                                .build();
        }

        // ==================== GET /api/categories Tests ====================

        @Nested
        @DisplayName("GET /api/categories")
        class GetAllCategoriesTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return all categories with 200 OK")
                void getAllCategories_Success() throws Exception {
                        when(categoryService.getAllCategories("testuser"))
                                        .thenReturn(Arrays.asList(defaultCategoryDTO, userCategoryDTO));

                        mockMvc.perform(get("/api/categories"))
                                        .andExpect(status().isOk())
                                        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                                        .andExpect(jsonPath("$", hasSize(2)))
                                        .andExpect(jsonPath("$[0].name").value("Social Media"))
                                        .andExpect(jsonPath("$[0].icon").value("social-icon"))
                                        .andExpect(jsonPath("$[0].isDefault").value(true))
                                        .andExpect(jsonPath("$[0].entryCount").value(10))
                                        .andExpect(jsonPath("$[1].name").value("My Custom Category"))
                                        .andExpect(jsonPath("$[1].icon").value("custom-icon"))
                                        .andExpect(jsonPath("$[1].isDefault").value(false))
                                        .andExpect(jsonPath("$[1].entryCount").value(5));

                        verify(categoryService).getAllCategories("testuser");
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return empty list when no categories")
                void getAllCategories_EmptyList() throws Exception {
                        when(categoryService.getAllCategories("testuser")).thenReturn(Collections.emptyList());

                        mockMvc.perform(get("/api/categories"))
                                        .andExpect(status().isOk())
                                        .andExpect(jsonPath("$", hasSize(0)));
                }

                @Test
                @DisplayName("Should return 401 when not authenticated")
                void getAllCategories_Unauthenticated() throws Exception {
                        mockMvc.perform(get("/api/categories"))
                                        .andExpect(status().isForbidden());
                }
        }

        // ==================== GET /api/categories/{id} Tests ====================

        @Nested
        @DisplayName("GET /api/categories/{id}")
        class GetCategoryByIdTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return category with 200 OK")
                void getCategoryById_Success() throws Exception {
                        when(categoryService.getCategoryById(1L, "testuser")).thenReturn(userCategoryDTO);

                        mockMvc.perform(get("/api/categories/1"))
                                        .andExpect(status().isOk())
                                        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                                        .andExpect(jsonPath("$.id").value(1))
                                        .andExpect(jsonPath("$.name").value("My Custom Category"))
                                        .andExpect(jsonPath("$.icon").value("custom-icon"))
                                        .andExpect(jsonPath("$.isDefault").value(false));

                        verify(categoryService).getCategoryById(1L, "testuser");
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return default category details")
                void getCategoryById_DefaultCategory_Success() throws Exception {
                        when(categoryService.getCategoryById(100L, "testuser")).thenReturn(defaultCategoryDTO);

                        mockMvc.perform(get("/api/categories/100"))
                                        .andExpect(status().isOk())
                                        .andExpect(jsonPath("$.id").value(100))
                                        .andExpect(jsonPath("$.name").value("Social Media"))
                                        .andExpect(jsonPath("$.icon").value("social-icon"))
                                        .andExpect(jsonPath("$.isDefault").value(true))
                                        .andExpect(jsonPath("$.entryCount").value(10));
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 404 when category not found")
                void getCategoryById_NotFound() throws Exception {
                        when(categoryService.getCategoryById(999L, "testuser"))
                                        .thenThrow(new ResourceNotFoundException("Category", "id", 999L));

                        mockMvc.perform(get("/api/categories/999"))
                                        .andExpect(status().isNotFound());
                }

                @Test
                @DisplayName("Should return 401 when not authenticated")
                void getCategoryById_Unauthenticated() throws Exception {
                        mockMvc.perform(get("/api/categories/1"))
                                        .andExpect(status().isForbidden());
                }
        }

        // ==================== POST /api/categories Tests ====================

        @Nested
        @DisplayName("POST /api/categories")
        class CreateCategoryTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should create category with 201 Created")
                void createCategory_Success() throws Exception {
                        CategoryDTO createdCategory = CategoryDTO.builder()
                                        .id(2L)
                                        .name("New Category")
                                        .icon("new-icon")
                                        .isDefault(false)
                                        .createdAt(LocalDateTime.now())
                                        .entryCount(0)
                                        .build();

                        when(categoryService.createCategory(any(CreateCategoryRequest.class), eq("testuser")))
                                        .thenReturn(createdCategory);

                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isCreated())
                                        .andExpect(jsonPath("$.id").value(2))
                                        .andExpect(jsonPath("$.name").value("New Category"))
                                        .andExpect(jsonPath("$.icon").value("new-icon"))
                                        .andExpect(jsonPath("$.isDefault").value(false))
                                        .andExpect(jsonPath("$.entryCount").value(0));

                        verify(categoryService).createCategory(any(CreateCategoryRequest.class), eq("testuser"));
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when name is blank")
                void createCategory_BlankName_BadRequest() throws Exception {
                        CreateCategoryRequest invalidRequest = CreateCategoryRequest.builder()
                                        .name("")
                                        .icon("icon")
                                        .build();

                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(invalidRequest)))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when name is null")
                void createCategory_NullName_BadRequest() throws Exception {
                        CreateCategoryRequest invalidRequest = CreateCategoryRequest.builder()
                                        .name(null)
                                        .icon("icon")
                                        .build();

                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(invalidRequest)))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when name exceeds max length")
                void createCategory_NameTooLong_BadRequest() throws Exception {
                        CreateCategoryRequest invalidRequest = CreateCategoryRequest.builder()
                                        .name("a".repeat(101)) // Max is 100
                                        .icon("icon")
                                        .build();

                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(invalidRequest)))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when duplicate name")
                void createCategory_DuplicateName_BadRequest() throws Exception {
                        when(categoryService.createCategory(any(CreateCategoryRequest.class), eq("testuser")))
                                        .thenThrow(new IllegalArgumentException(
                                                        "Category with name 'New Category' already exists"));

                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @DisplayName("Should return 401 when not authenticated")
                void createCategory_Unauthenticated() throws Exception {
                        mockMvc.perform(post("/api/categories")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isForbidden());
                }
        }

        // ==================== PUT /api/categories/{id} Tests ====================

        @Nested
        @DisplayName("PUT /api/categories/{id}")
        class UpdateCategoryTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should update category with 200 OK")
                void updateCategory_Success() throws Exception {
                        CreateCategoryRequest updateRequest = CreateCategoryRequest.builder()
                                        .name("Updated Category")
                                        .icon("updated-icon")
                                        .build();

                        CategoryDTO updatedCategory = CategoryDTO.builder()
                                        .id(1L)
                                        .name("Updated Category")
                                        .icon("updated-icon")
                                        .isDefault(false)
                                        .createdAt(LocalDateTime.now())
                                        .entryCount(5)
                                        .build();

                        when(categoryService.updateCategory(eq(1L), any(CreateCategoryRequest.class), eq("testuser")))
                                        .thenReturn(updatedCategory);

                        mockMvc.perform(put("/api/categories/1")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(updateRequest)))
                                        .andExpect(status().isOk())
                                        .andExpect(jsonPath("$.id").value(1))
                                        .andExpect(jsonPath("$.name").value("Updated Category"))
                                        .andExpect(jsonPath("$.icon").value("updated-icon"))
                                        .andExpect(jsonPath("$.isDefault").value(false))
                                        .andExpect(jsonPath("$.entryCount").value(5));

                        verify(categoryService).updateCategory(eq(1L), any(CreateCategoryRequest.class),
                                        eq("testuser"));
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 404 when category not found")
                void updateCategory_NotFound() throws Exception {
                        when(categoryService.updateCategory(eq(999L), any(CreateCategoryRequest.class), eq("testuser")))
                                        .thenThrow(new ResourceNotFoundException("Category", "id", 999L));

                        mockMvc.perform(put("/api/categories/999")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isNotFound());
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when updating default category")
                void updateCategory_DefaultCategory_BadRequest() throws Exception {
                        when(categoryService.updateCategory(eq(100L), any(CreateCategoryRequest.class), eq("testuser")))
                                        .thenThrow(new IllegalArgumentException("Cannot modify default categories"));

                        mockMvc.perform(put("/api/categories/100")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @DisplayName("Should return 401 when not authenticated")
                void updateCategory_Unauthenticated() throws Exception {
                        mockMvc.perform(put("/api/categories/1")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(objectMapper.writeValueAsString(createRequest)))
                                        .andExpect(status().isForbidden());
                }
        }

        // ==================== DELETE /api/categories/{id} Tests ====================

        @Nested
        @DisplayName("DELETE /api/categories/{id}")
        class DeleteCategoryTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should delete category with 204 No Content")
                void deleteCategory_Success() throws Exception {
                        doNothing().when(categoryService).deleteCategory(1L, "testuser");

                        mockMvc.perform(delete("/api/categories/1"))
                                        .andExpect(status().isOk());

                        verify(categoryService).deleteCategory(1L, "testuser");
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 404 when category not found")
                void deleteCategory_NotFound() throws Exception {
                        doThrow(new ResourceNotFoundException("Category", "id", 999L))
                                        .when(categoryService).deleteCategory(999L, "testuser");

                        mockMvc.perform(delete("/api/categories/999"))
                                        .andExpect(status().isNotFound());
                }

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return 400 when deleting default category")
                void deleteCategory_DefaultCategory_BadRequest() throws Exception {
                        doThrow(new IllegalArgumentException("Cannot delete default categories"))
                                        .when(categoryService).deleteCategory(100L, "testuser");

                        mockMvc.perform(delete("/api/categories/100"))
                                        .andExpect(status().isBadRequest());
                }

                @Test
                @DisplayName("Should return 401 when not authenticated")
                void deleteCategory_Unauthenticated() throws Exception {
                        mockMvc.perform(delete("/api/categories/1"))
                                        .andExpect(status().isForbidden());
                }
        }

        // ==================== GET /api/categories/{id}/entries Tests
        // ====================

        @Nested
        @DisplayName("GET /api/categories/{id}/entries")
        class GetEntriesInCategoryTests {

                @Test
                @WithMockUser(username = "testuser")
                @DisplayName("Should return entries in category with 200 OK")
                void getEntriesInCategory_ReturnsEntries() throws Exception {
                        VaultEntryResponse entry = VaultEntryResponse.builder()
                                        .id(1L)
                                        .title("Netflix")
                                        .username("******")
                                        .websiteUrl("https://netflix.com")
                                        .categoryId(1L)
                                        .categoryName("Entertainment")
                                        .isFavorite(false)
                                        .build();

                        when(vaultService.getEntriesByCategory("testuser", 1L))
                                        .thenReturn(Collections.singletonList(entry));

                        mockMvc.perform(get("/api/categories/1/entries"))
                                        .andExpect(status().isOk())
                                        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                                        .andExpect(jsonPath("$", hasSize(1)))
                                        .andExpect(jsonPath("$[0].title").value("Netflix"))
                                        .andExpect(jsonPath("$[0].categoryId").value(1));

                        verify(vaultService).getEntriesByCategory("testuser", 1L);
                }

                @Test
                @DisplayName("Should return 401 when not authenticated for entries in category")
                void getEntriesInCategory_Unauthenticated() throws Exception {
                        mockMvc.perform(get("/api/categories/1/entries"))
                                        .andExpect(status().isForbidden());
                }
        }
}
