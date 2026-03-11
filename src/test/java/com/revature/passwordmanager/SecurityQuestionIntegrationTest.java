package com.revature.passwordmanager;

import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.SecurityQuestionRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.service.auth.AuthenticationService;
import com.revature.passwordmanager.service.auth.SecurityQuestionService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = { "spring.sql.init.mode=never" })
@AutoConfigureTestDatabase
@Transactional
public class SecurityQuestionIntegrationTest {

  @Autowired
  private AuthenticationService authenticationService;

  @Autowired
  private SecurityQuestionService securityQuestionService;

  @Autowired
  private SecurityQuestionRepository securityQuestionRepository;

  @Autowired
  private UserRepository userRepository;

  @Test
  public void testGetSecurityQuestions() {
    // Setup user
    User user = User.builder()
        .username("testuser_sq")
        .email("testuser_sq@example.com")
        .masterPasswordHash("hash")
        .salt(UUID.randomUUID().toString())
        .createdAt(LocalDateTime.now())
        .updatedAt(LocalDateTime.now())
        .is2faEnabled(false)
        .build();

    user = userRepository.save(user);

    SecurityQuestionDTO q1 = new SecurityQuestionDTO("Q1", "A1");
    SecurityQuestionDTO q2 = new SecurityQuestionDTO("Q2", "A2");
    SecurityQuestionDTO q3 = new SecurityQuestionDTO("Q3", "A3");
    List<SecurityQuestionDTO> questions = List.of(q1, q2, q3);

    // Save security questions
    securityQuestionService.saveSecurityQuestions(user, questions);

    // Verify repository has questions
    assertEquals(3, securityQuestionRepository.findAllByUserId(user.getId()).size(),
        "Repository should have 3 questions");

    // Verify service returns questions using username
    List<SecurityQuestionDTO> retrieved = authenticationService.getSecurityQuestions("testuser_sq");
    assertEquals(3, retrieved.size(), "Service should return 3 questions");
    assertEquals("Q1", retrieved.get(0).getQuestion());
  }
}
