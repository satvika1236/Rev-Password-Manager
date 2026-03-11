package com.revature.passwordmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class ActuatorSecurityIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @Test
  void healthEndpointShouldBePublic() throws Exception {
    // The endpoint may report DOWN in tests if optional integrations like SMTP are unavailable.
    int status = mockMvc.perform(get("/actuator/health"))
        .andReturn()
        .getResponse()
        .getStatus();

    assertThat(status).isNotIn(401, 403);
  }
}
