package com.revature.passwordmanager.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitConfig {

  private int generalRequestsPerMinute = 60;
  private int authRequestsPerMinute = 10;
  private int passwordGeneratorRequestsPerMinute = 30;
}
