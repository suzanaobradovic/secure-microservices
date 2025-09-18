package app.userservice;

import app.userservice.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class UserServiceApplicationTests {

  @MockitoBean
  private JwtService jwtService;

  @Autowired
  private MockMvc mockMvc;

  @Test
  void contextLoads() {
  }

  @Test
  void actuatorHealthShouldReturnOk() throws Exception {
      mockMvc.perform(get("/actuator/health"))
             .andExpect(status().isOk());
  }

  @Test
  void authLoginShouldReturnBadRequestWithoutBody() throws Exception {
      mockMvc.perform(post("/auth/login"))
             .andExpect(status().isBadRequest());
  }
}
