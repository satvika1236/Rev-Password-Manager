package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.SecurityQuestionDTO;
import com.revature.passwordmanager.model.user.SecurityQuestion;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.SecurityQuestionRepository;
import com.revature.passwordmanager.service.auth.SecurityQuestionService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityQuestionServiceTest {

  @Mock
  private SecurityQuestionRepository securityQuestionRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private SecurityQuestionService securityQuestionService;

  private User user;
  private List<SecurityQuestionDTO> dtoList;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setId(1L);
    user.setUsername("testuser");

    SecurityQuestionDTO q1 = new SecurityQuestionDTO("Q1", "Answer1");
    SecurityQuestionDTO q2 = new SecurityQuestionDTO("Q2", "Answer2");
    dtoList = Arrays.asList(q1, q2);
  }

  @Test
  void testSaveSecurityQuestions() {
    when(passwordEncoder.encode(anyString())).thenReturn("hashedAnswer");

    securityQuestionService.saveSecurityQuestions(user, dtoList);

    verify(securityQuestionRepository).deleteAllByUserId(user.getId());
    verify(securityQuestionRepository).saveAll(anyList());
    verify(passwordEncoder, times(2)).encode(anyString());
  }

  @Test
  void testVerifySecurityAnswers_Success() {
    SecurityQuestion sq1 = new SecurityQuestion(1L, user, "Q1", "hashedAnswer1");
    SecurityQuestion sq2 = new SecurityQuestion(2L, user, "Q2", "hashedAnswer2");
    List<SecurityQuestion> storedList = Arrays.asList(sq1, sq2);

    when(securityQuestionRepository.findAllByUserId(user.getId())).thenReturn(storedList);
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

    boolean result = securityQuestionService.verifySecurityAnswers(user, dtoList);

    assertTrue(result);
  }

  @Test
  void testVerifySecurityAnswers_Fail() {
    SecurityQuestion sq1 = new SecurityQuestion(1L, user, "Q1", "hashedAnswer1");
    List<SecurityQuestion> storedList = Collections.singletonList(sq1);

    when(securityQuestionRepository.findAllByUserId(user.getId())).thenReturn(storedList);
    // Fail match
    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

    boolean result = securityQuestionService.verifySecurityAnswers(user, Collections.singletonList(dtoList.get(0)));

    assertFalse(result);
  }
}
