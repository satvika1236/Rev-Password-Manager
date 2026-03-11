package com.revature.passwordmanager.service.email;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

  @Mock
  private JavaMailSender javaMailSender;

  @InjectMocks
  private EmailService emailService;

  @Test
  void sendOtpEmail_Success() {
    ReflectionTestUtils.setField(emailService, "fromEmail", "test@example.com");

    MimeMessage mimeMessage = mock(MimeMessage.class);
    when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);

    emailService.sendOtpEmail("test@example.com", "123456");

    verify(javaMailSender).send(mimeMessage);
  }
}
