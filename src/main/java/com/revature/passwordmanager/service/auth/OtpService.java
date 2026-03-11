package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.exception.AuthenticationException;
import com.revature.passwordmanager.model.auth.OtpToken;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.OtpTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class OtpService {

  private final OtpTokenRepository otpTokenRepository;
  private static final SecureRandom secureRandom = new SecureRandom();
  private static final int OTP_LENGTH = 6;
  private static final int EXPIRY_MINUTES = 15;

  @Transactional
  public String generateOtp(User user, String type) {

    String token = String.format("%06d", secureRandom.nextInt(1000000));

    OtpToken otpToken = OtpToken.builder()
        .user(user)
        .token(token)
        .tokenType(type)
        .expiryDate(LocalDateTime.now().plusMinutes(EXPIRY_MINUTES))
        .isUsed(false)
        .build();

    otpTokenRepository.save(otpToken);
    return token;
  }

  @Transactional
  public boolean validateOtp(User user, String token, String type) {
    OtpToken otpToken = otpTokenRepository.findByToken(token)
        .orElseThrow(() -> new AuthenticationException("Invalid OTP"));

    if (!otpToken.getUser().getId().equals(user.getId())) {
      throw new AuthenticationException("Invalid OTP for user");
    }

    if (type != null && !type.equals(otpToken.getTokenType())) {
      throw new AuthenticationException("Invalid OTP type");
    }

    if (otpToken.isUsed()) {
      throw new AuthenticationException("OTP already used");
    }

    if (otpToken.getExpiryDate().isBefore(LocalDateTime.now())) {
      throw new AuthenticationException("OTP expired");
    }

    otpToken.setUsed(true);
    otpTokenRepository.save(otpToken);
    return true;
  }
}
