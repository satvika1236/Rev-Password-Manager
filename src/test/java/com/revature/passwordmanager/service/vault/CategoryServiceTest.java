package com.revature.passwordmanager.service.vault;

import com.revature.passwordmanager.dto.CategoryDTO;
import com.revature.passwordmanager.dto.request.CreateCategoryRequest;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.Category;
import com.revature.passwordmanager.repository.CategoryRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.vault.CategoryService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CategoryServiceTest {

  @Mock
  private CategoryRepository categoryRepository;

  @Mock
  private UserRepository userRepository;

  @InjectMocks
  private CategoryService categoryService;

  private User testUser;
  private Category userCategory;
  private Category defaultCategory;
  private CreateCategoryRequest createRequest;

  @BeforeEach
  void setUp() {
    testUser = User.builder()
        .id(1L)
        .username("testuser")
        .email("test@example.com")
        .build();

    userCategory = Category.builder()
        .id(1L)
        .user(testUser)
        .name("My Custom Category")
        .icon("custom-icon")
        .isDefault(false)
        .createdAt(LocalDateTime.now())
        .build();

    defaultCategory = Category.builder()
        .id(100L)
        .user(null)
        .name("Social Media")
        .icon("social-icon")
        .isDefault(true)
        .createdAt(LocalDateTime.now())
        .build();

    createRequest = CreateCategoryRequest.builder()
        .name("New Category")
        .icon("new-icon")
        .build();
  }

  // ==================== getAllCategories Tests ====================

  @Nested
  @DisplayName("getAllCategories")
  class GetAllCategoriesTests {

    @Test
    @DisplayName("Should return both default and user categories")
    void getAllCategories_ReturnsDefaultAndUserCategories() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByUserIdOrderByNameAsc(1L)).thenReturn(Collections.singletonList(userCategory));
      when(categoryRepository.findByUserIdIsNullAndIsDefaultTrue())
          .thenReturn(Collections.singletonList(defaultCategory));

      List<CategoryDTO> result = categoryService.getAllCategories("testuser");

      assertNotNull(result);
      assertEquals(2, result.size());

      // Default categories should come first
      assertTrue(result.get(0).getIsDefault());
      assertEquals("Social Media", result.get(0).getName());

      // User categories should come after
      assertFalse(result.get(1).getIsDefault());
      assertEquals("My Custom Category", result.get(1).getName());

      verify(categoryRepository).findByUserIdOrderByNameAsc(1L);
      verify(categoryRepository).findByUserIdIsNullAndIsDefaultTrue();
    }

    @Test
    @DisplayName("Should throw exception when user not found")
    void getAllCategories_UserNotFound_ThrowsException() {
      when(userRepository.findByUsernameOrThrow("unknown")).thenThrow(new ResourceNotFoundException("User not found"));

      assertThrows(ResourceNotFoundException.class,
          () -> categoryService.getAllCategories("unknown"));
    }

    @Test
    @DisplayName("Should return only default categories when user has none")
    void getAllCategories_NoUserCategories_ReturnsOnlyDefaults() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByUserIdOrderByNameAsc(1L)).thenReturn(Collections.emptyList());
      when(categoryRepository.findByUserIdIsNullAndIsDefaultTrue())
          .thenReturn(Collections.singletonList(defaultCategory));

      List<CategoryDTO> result = categoryService.getAllCategories("testuser");

      assertEquals(1, result.size());
      assertTrue(result.get(0).getIsDefault());
    }
  }

  // ==================== getCategoryById Tests ====================

  @Nested
  @DisplayName("getCategoryById")
  class GetCategoryByIdTests {

    @Test
    @DisplayName("Should return user's own category")
    void getCategoryById_UserCategory_Success() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(userCategory));

      CategoryDTO result = categoryService.getCategoryById(1L, "testuser");

      assertNotNull(result);
      assertEquals(1L, result.getId());
      assertEquals("My Custom Category", result.getName());
      assertFalse(result.getIsDefault());
    }

    @Test
    @DisplayName("Should return default category when user doesn't own it")
    void getCategoryById_DefaultCategory_Success() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(100L, 1L)).thenReturn(Optional.empty());
      when(categoryRepository.findById(100L)).thenReturn(Optional.of(defaultCategory));

      CategoryDTO result = categoryService.getCategoryById(100L, "testuser");

      assertNotNull(result);
      assertEquals(100L, result.getId());
      assertEquals("Social Media", result.getName());
      assertTrue(result.getIsDefault());
    }

    @Test
    @DisplayName("Should throw exception when category not found")
    void getCategoryById_NotFound_ThrowsException() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(999L, 1L)).thenReturn(Optional.empty());
      when(categoryRepository.findById(999L)).thenReturn(Optional.empty());

      assertThrows(ResourceNotFoundException.class,
          () -> categoryService.getCategoryById(999L, "testuser"));
    }
  }

  // ==================== createCategory Tests ====================

  @Nested
  @DisplayName("createCategory")
  class CreateCategoryTests {

    @Test
    @DisplayName("Should create category successfully")
    void createCategory_Success() {
      Category savedCategory = Category.builder()
          .id(2L)
          .user(testUser)
          .name("New Category")
          .icon("new-icon")
          .isDefault(false)
          .createdAt(LocalDateTime.now())
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.existsByUserIdAndName(1L, "New Category")).thenReturn(false);
      when(categoryRepository.save(any(Category.class))).thenReturn(savedCategory);

      CategoryDTO result = categoryService.createCategory(createRequest, "testuser");

      assertNotNull(result);
      assertEquals("New Category", result.getName());
      assertEquals("new-icon", result.getIcon());
      assertFalse(result.getIsDefault()); // User categories are never default

      verify(categoryRepository).save(any(Category.class));
    }

    @Test
    @DisplayName("Should always set isDefault to false for user-created categories")
    void createCategory_IsDefaultAlwaysFalse() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.existsByUserIdAndName(1L, "New Category")).thenReturn(false);
      when(categoryRepository.save(any(Category.class))).thenAnswer(invocation -> {
        Category saved = invocation.getArgument(0);
        // Verify that isDefault is set to false
        assertFalse(saved.getIsDefault());
        saved.setId(2L);
        saved.setCreatedAt(LocalDateTime.now());
        return saved;
      });

      categoryService.createCategory(createRequest, "testuser");

      verify(categoryRepository).save(argThat(category -> Boolean.FALSE.equals(category.getIsDefault())));
    }

    @Test
    @DisplayName("Should throw exception when category name already exists")
    void createCategory_DuplicateName_ThrowsException() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.existsByUserIdAndName(1L, "New Category")).thenReturn(true);

      IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
          () -> categoryService.createCategory(createRequest, "testuser"));

      assertTrue(exception.getMessage().contains("already exists"));
      verify(categoryRepository, never()).save(any());
    }
  }

  // ==================== updateCategory Tests ====================

  @Nested
  @DisplayName("updateCategory")
  class UpdateCategoryTests {

    @Test
    @DisplayName("Should update category successfully")
    void updateCategory_Success() {
      CreateCategoryRequest updateRequest = CreateCategoryRequest.builder()
          .name("Updated Name")
          .icon("updated-icon")
          .build();

      Category updatedCategory = Category.builder()
          .id(1L)
          .user(testUser)
          .name("Updated Name")
          .icon("updated-icon")
          .isDefault(false)
          .createdAt(userCategory.getCreatedAt())
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(userCategory));
      when(categoryRepository.findByUserIdAndName(1L, "Updated Name")).thenReturn(Optional.empty());
      when(categoryRepository.save(any(Category.class))).thenReturn(updatedCategory);

      CategoryDTO result = categoryService.updateCategory(1L, updateRequest, "testuser");

      assertNotNull(result);
      assertEquals("Updated Name", result.getName());
      assertEquals("updated-icon", result.getIcon());
    }

    @Test
    @DisplayName("Should throw exception when updating default category")
    void updateCategory_DefaultCategory_ThrowsException() {
      // Make the category a default one for this test
      Category defaultCat = Category.builder()
          .id(1L)
          .user(testUser)
          .name("Default Cat")
          .icon("icon")
          .isDefault(true)
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(defaultCat));

      IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
          () -> categoryService.updateCategory(1L, createRequest, "testuser"));

      assertTrue(exception.getMessage().contains("Cannot modify default categories"));
      verify(categoryRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should throw exception when new name already exists")
    void updateCategory_DuplicateName_ThrowsException() {
      Category existingCategory = Category.builder()
          .id(2L)
          .user(testUser)
          .name("New Category")
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(userCategory));
      when(categoryRepository.findByUserIdAndName(1L, "New Category")).thenReturn(Optional.of(existingCategory));

      assertThrows(IllegalArgumentException.class,
          () -> categoryService.updateCategory(1L, createRequest, "testuser"));
    }

    @Test
    @DisplayName("Should allow updating with same name (no change)")
    void updateCategory_SameName_Success() {
      CreateCategoryRequest sameNameRequest = CreateCategoryRequest.builder()
          .name("My Custom Category")
          .icon("different-icon")
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(userCategory));
      when(categoryRepository.findByUserIdAndName(1L, "My Custom Category")).thenReturn(Optional.of(userCategory));
      when(categoryRepository.save(any(Category.class))).thenReturn(userCategory);

      CategoryDTO result = categoryService.updateCategory(1L, sameNameRequest, "testuser");

      assertNotNull(result);
      verify(categoryRepository).save(any());
    }

    @Test
    @DisplayName("Should throw exception when category not found")
    void updateCategory_NotFound_ThrowsException() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(999L, 1L)).thenReturn(Optional.empty());

      assertThrows(ResourceNotFoundException.class,
          () -> categoryService.updateCategory(999L, createRequest, "testuser"));
    }
  }

  // ==================== deleteCategory Tests ====================

  @Nested
  @DisplayName("deleteCategory")
  class DeleteCategoryTests {

    @Test
    @DisplayName("Should delete category successfully")
    void deleteCategory_Success() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(userCategory));
      doNothing().when(categoryRepository).delete(userCategory);

      assertDoesNotThrow(() -> categoryService.deleteCategory(1L, "testuser"));

      verify(categoryRepository).delete(userCategory);
    }

    @Test
    @DisplayName("Should throw exception when deleting default category")
    void deleteCategory_DefaultCategory_ThrowsException() {
      Category defaultCat = Category.builder()
          .id(1L)
          .user(testUser)
          .name("Default Cat")
          .isDefault(true)
          .build();

      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(1L, 1L)).thenReturn(Optional.of(defaultCat));

      IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
          () -> categoryService.deleteCategory(1L, "testuser"));

      assertTrue(exception.getMessage().contains("Cannot delete default categories"));
      verify(categoryRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Should throw exception when category not found")
    void deleteCategory_NotFound_ThrowsException() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.findByIdAndUserId(999L, 1L)).thenReturn(Optional.empty());

      assertThrows(ResourceNotFoundException.class,
          () -> categoryService.deleteCategory(999L, "testuser"));
    }
  }

  // ==================== getCategoryCount Tests ====================

  @Nested
  @DisplayName("getCategoryCount")
  class GetCategoryCountTests {

    @Test
    @DisplayName("Should return correct count")
    void getCategoryCount_Success() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.countByUserId(1L)).thenReturn(5L);

      long count = categoryService.getCategoryCount("testuser");

      assertEquals(5L, count);
    }

    @Test
    @DisplayName("Should return zero when no categories")
    void getCategoryCount_NoCategories_ReturnsZero() {
      when(userRepository.findByUsernameOrThrow("testuser")).thenReturn(testUser);
      when(categoryRepository.countByUserId(1L)).thenReturn(0L);

      long count = categoryService.getCategoryCount("testuser");

      assertEquals(0L, count);
    }
  }
}
