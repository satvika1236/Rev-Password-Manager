package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.dto.request.RecoveryRequest;
import com.revature.passwordmanager.dto.request.ForgotPasswordRequest;
import com.revature.passwordmanager.dto.request.VerifySecurityQuestionsRequest;
import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AccountRecoveryService {

  private final UserRepository userRepository;
  private final SecurityQuestionService securityQuestionService;
  private final PasswordEncoder passwordEncoder;
  private final SessionService sessionService;

  @Transactional
  public void resetPassword(RecoveryRequest request) {
    User user = userRepository.findByUsername(request.getUsername())
        .or(() -> userRepository.findByEmail(request.getUsername()))
        .orElseThrow(() -> new AuthenticationException("User not found"));

    if (!securityQuestionService.verifySecurityAnswers(user, request.getSecurityAnswers())) {
      throw new AuthenticationException("Invalid security answers");
    }

    user.setMasterPasswordHash(passwordEncoder.encode(request.getNewMasterPassword()));
    user.setUpdatedAt(LocalDateTime.now());
    userRepository.save(user);

    sessionService.terminateAllUserSessions(user.getUsername());
  }

  @Transactional
  public void forgotPassword(ForgotPasswordRequest request) {
    userRepository.findByUsername(request.getUsername())
        .or(() -> userRepository.findByEmail(request.getUsername()))
        .orElseThrow(() -> new AuthenticationException("User not found"));

  }

  @Transactional
  public void verifySecurityQuestions(VerifySecurityQuestionsRequest request) {
    User user = userRepository.findByUsername(request.getUsername())
        .or(() -> userRepository.findByEmail(request.getUsername()))
        .orElseThrow(() -> new AuthenticationException("User not found"));

    if (!securityQuestionService.verifySecurityAnswers(user, request.getSecurityAnswers())) {
      throw new AuthenticationException("Invalid security answers");
    }
  }
}
