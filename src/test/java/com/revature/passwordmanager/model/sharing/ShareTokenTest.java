package com.revature.passwordmanager.model.sharing;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ShareToken}.
 *
 * <p>Gap closure: {@code ShareToken} was proposed in the Feature 35 spec as a dedicated
 * class to wrap the raw UUID token string. It was missing from the implementation —
 * token generation was a plain {@code String}. This class provides the rich value
 * object with expiry awareness that the spec intended.</p>
 */
class ShareTokenTest {

    // ── factory: ShareToken.of ────────────────────────────────────────────────

    @Test
    void of_ShouldPopulateAllFields() {
        String rawToken = "550e8400-e29b-41d4-a716-446655440000";
        ShareToken token = ShareToken.of(rawToken, 24);

        assertThat(token.getValue()).isEqualTo(rawToken);
        assertThat(token.getCreatedAt()).isNotNull();
        assertThat(token.getExpiresAt()).isNotNull();
        assertThat(token.getExpiresAt()).isAfter(token.getCreatedAt());
    }

    @Test
    void of_ExpiryHours_ShouldComputeCorrectExpiry() {
        LocalDateTime before = LocalDateTime.now();
        ShareToken token = ShareToken.of("some-uuid", 48);
        LocalDateTime after = LocalDateTime.now();

        assertThat(token.getExpiresAt())
                .isAfterOrEqualTo(before.plusHours(47))
                .isBeforeOrEqualTo(after.plusHours(49));
    }

    @Test
    void of_ZeroExpiryHours_ShouldExpireImmediately() {
        ShareToken token = ShareToken.of("expire-now-uuid", 0);

        // With 0 hours, expiresAt == createdAt → should be expired
        assertThat(token.isExpired()).isTrue();
    }

    // ── isExpired / isValid ───────────────────────────────────────────────────

    @Test
    void isExpired_FutureExpiry_ShouldReturnFalse() {
        ShareToken token = ShareToken.builder()
                .value("tok1")
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusHours(24))
                .build();

        assertThat(token.isExpired()).isFalse();
        assertThat(token.isValid()).isTrue();
    }

    @Test
    void isExpired_PastExpiry_ShouldReturnTrue() {
        ShareToken token = ShareToken.builder()
                .value("tok2")
                .createdAt(LocalDateTime.now().minusDays(2))
                .expiresAt(LocalDateTime.now().minusDays(1))
                .build();

        assertThat(token.isExpired()).isTrue();
        assertThat(token.isValid()).isFalse();
    }

    @Test
    void isValid_IsOppositeOfIsExpired_FutureExpiry() {
        ShareToken token = ShareToken.builder()
                .value("tok3")
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .build();

        assertThat(token.isValid()).isEqualTo(!token.isExpired());
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    @Test
    void builder_AllFields_ShouldBeSet() {
        LocalDateTime created = LocalDateTime.of(2026, 1, 1, 10, 0);
        LocalDateTime expires = LocalDateTime.of(2026, 1, 2, 10, 0);

        ShareToken token = ShareToken.builder()
                .value("custom-token-value")
                .createdAt(created)
                .expiresAt(expires)
                .build();

        assertThat(token.getValue()).isEqualTo("custom-token-value");
        assertThat(token.getCreatedAt()).isEqualTo(created);
        assertThat(token.getExpiresAt()).isEqualTo(expires);
    }

    // ── Equality ──────────────────────────────────────────────────────────────

    @Test
    void twoTokensWithSameFields_ShouldBeEqual() {
        LocalDateTime ts = LocalDateTime.of(2026, 2, 1, 12, 0);
        LocalDateTime exp = ts.plusHours(24);

        ShareToken t1 = ShareToken.builder().value("abc").createdAt(ts).expiresAt(exp).build();
        ShareToken t2 = ShareToken.builder().value("abc").createdAt(ts).expiresAt(exp).build();

        assertThat(t1).isEqualTo(t2);
        assertThat(t1.hashCode()).isEqualTo(t2.hashCode());
    }

    @Test
    void twoTokensWithDifferentValues_ShouldNotBeEqual() {
        LocalDateTime ts = LocalDateTime.of(2026, 2, 1, 12, 0);

        ShareToken t1 = ShareToken.builder().value("abc").createdAt(ts).expiresAt(ts.plusHours(1)).build();
        ShareToken t2 = ShareToken.builder().value("xyz").createdAt(ts).expiresAt(ts.plusHours(1)).build();

        assertThat(t1).isNotEqualTo(t2);
    }

    // ── toString ──────────────────────────────────────────────────────────────

    @Test
    void toString_ShouldContainValue() {
        ShareToken token = ShareToken.builder()
                .value("my-token-id")
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build();

        assertThat(token.toString()).contains("my-token-id");
    }
}
