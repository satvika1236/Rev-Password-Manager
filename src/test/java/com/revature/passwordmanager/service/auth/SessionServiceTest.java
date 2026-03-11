package com.revature.passwordmanager.service.auth;

import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.user.UserSession;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.UserSessionRepository;
import com.revature.passwordmanager.service.auth.SessionService;
import com.revature.passwordmanager.util.ClientIpUtil;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

  @Mock
  private UserSessionRepository userSessionRepository;

  @Mock
  private UserRepository userRepository;

  @Mock
  private ClientIpUtil clientIpUtil;

  @InjectMocks
  private SessionService sessionService;

  private User user;
  private UserSession session;
  private HttpServletRequest request;

  @BeforeEach
  void setUp() {
    user = new User();
    user.setId(1L);
    user.setUsername("testuser");
    user.setEmail("test@example.com");

    session = UserSession.builder()
            .id(100L)
            .user(user)
            .token("jwt-token")
            .isActive(true)
            .build();

    request = mock(HttpServletRequest.class);
  }

  @Test
  void testCreateSession() {
    when(clientIpUtil.getClientIpAddress(request)).thenReturn("127.0.0.1");
    when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");

    sessionService.createSession(user, "jwt-token", request, "Unknown", "fingerprint123");

    verify(userSessionRepository).save(any(UserSession.class));
  }

  @Test
  void testIsSessionActive_True() {
    when(userSessionRepository.findFirstByTokenOrderByIdDesc("jwt-token")).thenReturn(Optional.of(session));

    boolean isActive = sessionService.isSessionActive("jwt-token");

    assertTrue(isActive);
  }

  @Test
  void testIsSessionActive_False() {
    session.setActive(false);
    when(userSessionRepository.findFirstByTokenOrderByIdDesc("jwt-token")).thenReturn(Optional.of(session));

    boolean isActive = sessionService.isSessionActive("jwt-token");

    assertFalse(isActive);
  }

  @Test
  void testTerminateSession_Success() {
    when(userSessionRepository.findById(100L)).thenReturn(Optional.of(session));

    sessionService.terminateSession(100L, "testuser");

    assertFalse(session.isActive());
    verify(userSessionRepository).save(session);
  }

  @Test
  void testTerminateSession_WrongUser() {
    User otherUser = new User();
    otherUser.setId(2L);
    otherUser.setUsername("otheruser");

    // Create a session belonging to OTHER user
    UserSession otherSession = UserSession.builder()
            .id(100L)
            .user(otherUser)
            .isActive(true)
            .build();

    when(userSessionRepository.findById(100L)).thenReturn(Optional.of(otherSession));

    assertThrows(ResourceNotFoundException.class, () -> sessionService.terminateSession(100L, "testuser"));
    verify(userSessionRepository, never()).save(otherSession);
  }

  @Test
  void testTerminateAllUserSessions() {
    UserSession session2 = UserSession.builder().id(101L).user(user).isActive(true).build();
    List<UserSession> sessions = List.of(session, session2);

    when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
    when(userSessionRepository.findByUserIdAndIsActiveTrue(1L)).thenReturn(sessions);

    sessionService.terminateAllUserSessions("testuser");

    assertFalse(session.isActive());
    assertFalse(session2.isActive());
    verify(userSessionRepository).saveAll(sessions);
  }

  @Test
  void testGetCurrentSession_Success() {
    String token = "validToken";
    UserSession session = new UserSession();
    session.setId(1L);
    session.setToken(token);
    session.setActive(true);

    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.of(session));

    var response = sessionService.getCurrentSession(token);

    assertNotNull(response);
    assertEquals(1L, response.getId());
    assertTrue(response.isActive());
  }

  @Test
  void testGetCurrentSession_NotFound() {
    String token = "invalidToken";
    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.empty());

    assertThrows(ResourceNotFoundException.class, () -> sessionService.getCurrentSession(token));
  }

  @Test
  void testTerminateSessionByToken_Success() {
    String token = "validToken";
    UserSession session = new UserSession();
    session.setId(1L);
    session.setToken(token);
    session.setActive(true);
    // Set user for logging
    User user = new User();
    user.setUsername("testuser");
    session.setUser(user);

    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.of(session));

    sessionService.terminateSessionByToken(token);

    assertFalse(session.isActive());
    verify(userSessionRepository).save(session);
  }

  @Test
  void testTerminateSessionByToken_NotFound() {
    verify(userSessionRepository, never()).save(any(UserSession.class));
  }

  @Test
  void testExtendSession_Success() {
    String token = "validToken";
    UserSession session = new UserSession();
    session.setId(1L);
    session.setToken(token);
    session.setActive(true);
    // Set user for logging
    User user = new User();
    user.setUsername("testuser");
    session.setUser(user);

    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.of(session));

    var response = sessionService.extendSession(token);

    assertNotNull(response);
    assertEquals(1L, response.getId());
    verify(userSessionRepository).save(session);
  }

  @Test
  void testExtendSession_InactiveSession() {
    String token = "validToken";
    UserSession session = new UserSession();
    session.setId(1L);
    session.setToken(token);
    session.setActive(false);

    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.of(session));

    assertThrows(com.revature.passwordmanager.exception.AuthenticationException.class,
            () -> sessionService.extendSession(token));
  }

  @Test
  void testExtendSession_NotFound() {
    String token = "invalidToken";
    when(userSessionRepository.findFirstByTokenOrderByIdDesc(token)).thenReturn(Optional.empty());

    assertThrows(ResourceNotFoundException.class, () -> sessionService.extendSession(token));
  }
}
