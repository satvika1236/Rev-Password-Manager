package com.revature.passwordmanager.service.sharing;

import com.revature.passwordmanager.repository.SecureShareRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ShareTokenGeneratorTest {

    @Mock
    private SecureShareRepository shareRepository;

    @InjectMocks
    private ShareTokenGenerator generator;

    @Test
    void generate_ShouldReturnNonNullToken() {
        when(shareRepository.existsByShareToken(anyString())).thenReturn(false);
        String token = generator.generate();
        assertNotNull(token);
    }

    @Test
    void generate_ShouldReturn32CharHexToken() {
        when(shareRepository.existsByShareToken(anyString())).thenReturn(false);
        String token = generator.generate();
        // UUID v4 without hyphens = 32 hex chars
        assertEquals(32, token.length());
        assertTrue(token.matches("[0-9a-f]{32}"), "Token should be lowercase hex: " + token);
    }

    @Test
    void generate_ShouldProduceUniqueTokens() {
        when(shareRepository.existsByShareToken(anyString())).thenReturn(false);
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            tokens.add(generator.generate());
        }
        assertEquals(100, tokens.size(), "All generated tokens should be unique");
    }

    @Test
    void generate_WhenFirstTokenCollides_ShouldRetryAndSucceed() {
        // First call returns collision, second is unique
        when(shareRepository.existsByShareToken(anyString()))
                .thenReturn(true)
                .thenReturn(false);

        String token = generator.generate();
        assertNotNull(token);
        assertEquals(32, token.length());
        verify(shareRepository, times(2)).existsByShareToken(anyString());
    }

    @Test
    void generate_WhenAllAttemptsCollide_ShouldThrowIllegalStateException() {
        when(shareRepository.existsByShareToken(anyString())).thenReturn(true);

        assertThrows(IllegalStateException.class, () -> generator.generate());
        verify(shareRepository, times(5)).existsByShareToken(anyString());
    }

    @Test
    void generate_ShouldNotContainHyphens() {
        when(shareRepository.existsByShareToken(anyString())).thenReturn(false);
        String token = generator.generate();
        assertFalse(token.contains("-"), "Token should not contain hyphens");
    }
}
