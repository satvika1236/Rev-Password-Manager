package com.revature.passwordmanager.service.sharing;

import com.revature.passwordmanager.model.sharing.SecureShare;
import com.revature.passwordmanager.model.sharing.SharePermission;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.SecureShareRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ShareExpirationService}.
 *
 * <p>Gap closure: this service was proposed in the Feature 35 spec but was missing.
 * Its responsibilities were previously scattered across {@code SecureShare.isValid()},
 * {@code SecureShareCleanupScheduler}, and inline service logic. Extracting them here
 * provides a single, properly-tested unit for all share expiration concerns.</p>
 */
@ExtendWith(MockitoExtension.class)
class ShareExpirationServiceTest {

    @Mock
    private SecureShareRepository shareRepository;

    @InjectMocks
    private ShareExpirationService expirationService;

    private User alice;
    private VaultEntry netflixEntry;

    @BeforeEach
    void setUp() {
        alice = User.builder().id(1L).username("alice").build();
        netflixEntry = VaultEntry.builder().id(10L).title("Netflix").user(alice).build();
    }

    // ── isValid ───────────────────────────────────────────────────────────────

    @Test
    void isValid_ActiveViewOnceShare_NotYetViewed_ShouldBeValid() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.isValid(share)).isTrue();
    }

    @Test
    void isValid_ViewOnceShare_AlreadyViewed_ShouldBeInvalid() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 1, false,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.isValid(share)).isFalse();
    }

    @Test
    void isValid_ExpiredShare_ShouldBeInvalid() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 5, 0, false,
                LocalDateTime.now().minusSeconds(1));

        assertThat(expirationService.isValid(share)).isFalse();
    }

    @Test
    void isValid_RevokedShare_ShouldBeInvalid() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 5, 0, true,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.isValid(share)).isFalse();
    }

    @Test
    void isValid_NullShare_ShouldReturnFalse() {
        assertThat(expirationService.isValid(null)).isFalse();
    }

    @Test
    void isValid_TemporaryAccessShare_WithinTime_ShouldBeValid() {
        SecureShare share = buildShare(SharePermission.TEMPORARY_ACCESS, Integer.MAX_VALUE, 999, false,
                LocalDateTime.now().plusHours(72));

        // TEMPORARY_ACCESS ignores view count
        assertThat(expirationService.isValid(share)).isTrue();
    }

    @Test
    void isValid_ViewMultipleShare_PartiallyViewed_ShouldBeValid() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 5, 3, false,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.isValid(share)).isTrue();
    }

    @Test
    void isValid_ViewMultipleShare_ViewLimitReached_ShouldBeInvalid() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 5, 5, false,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.isValid(share)).isFalse();
    }

    // ── isViewLimitReached ────────────────────────────────────────────────────

    @Test
    void isViewLimitReached_ViewOnce_AfterOneView_ShouldBeTrue() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 1, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.isViewLimitReached(share)).isTrue();
    }

    @Test
    void isViewLimitReached_TemporaryAccess_NeverReached() {
        SecureShare share = buildShare(SharePermission.TEMPORARY_ACCESS, Integer.MAX_VALUE, 10000, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.isViewLimitReached(share)).isFalse();
    }

    @Test
    void isViewLimitReached_ViewMultiple_BelowLimit_ShouldBeFalse() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 10, 5, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.isViewLimitReached(share)).isFalse();
    }

    // ── isExpired ─────────────────────────────────────────────────────────────

    @Test
    void isExpired_FutureExpiry_ShouldBeFalse() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().plusMinutes(5));

        assertThat(expirationService.isExpired(share)).isFalse();
    }

    @Test
    void isExpired_PastExpiry_ShouldBeTrue() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().minusMinutes(1));

        assertThat(expirationService.isExpired(share)).isTrue();
    }

    // ── secondsUntilExpiry ────────────────────────────────────────────────────

    @Test
    void secondsUntilExpiry_FutureShare_ShouldReturnPositiveSeconds() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().plusHours(1));

        long seconds = expirationService.secondsUntilExpiry(share);

        assertThat(seconds).isGreaterThan(3500).isLessThanOrEqualTo(3600);
    }

    @Test
    void secondsUntilExpiry_ExpiredShare_ShouldReturnZero() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().minusHours(1));

        assertThat(expirationService.secondsUntilExpiry(share)).isZero();
    }

    // ── viewsRemaining ────────────────────────────────────────────────────────

    @Test
    void viewsRemaining_ViewOnceNotViewed_ShouldReturn1() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.viewsRemaining(share)).isEqualTo(1);
    }

    @Test
    void viewsRemaining_ViewOnceAlreadyViewed_ShouldReturn0() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 1, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.viewsRemaining(share)).isZero();
    }

    @Test
    void viewsRemaining_TemporaryAccess_ShouldReturnMaxInt() {
        SecureShare share = buildShare(SharePermission.TEMPORARY_ACCESS, Integer.MAX_VALUE, 5, false,
                LocalDateTime.now().plusHours(72));

        assertThat(expirationService.viewsRemaining(share)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void viewsRemaining_ViewMultiple_PartiallyConsumed_ShouldReturnRemainder() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 10, 7, false,
                LocalDateTime.now().plusHours(24));

        assertThat(expirationService.viewsRemaining(share)).isEqualTo(3);
    }

    // ── getInvalidReason ──────────────────────────────────────────────────────

    @Test
    void getInvalidReason_ValidShare_ShouldReturnNull() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.getInvalidReason(share)).isNull();
    }

    @Test
    void getInvalidReason_RevokedShare_ShouldReturnRevoked() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, true,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.getInvalidReason(share)).isEqualTo("revoked");
    }

    @Test
    void getInvalidReason_ExpiredShare_ShouldReturnExpired() {
        SecureShare share = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().minusMinutes(10));

        assertThat(expirationService.getInvalidReason(share)).isEqualTo("expired");
    }

    @Test
    void getInvalidReason_ViewLimitExceeded_ShouldReturnViewLimitReached() {
        SecureShare share = buildShare(SharePermission.VIEW_MULTIPLE, 3, 3, false,
                LocalDateTime.now().plusHours(1));

        assertThat(expirationService.getInvalidReason(share)).isEqualTo("view limit reached");
    }

    // ── deleteExpiredShares ───────────────────────────────────────────────────

    @Test
    void deleteExpiredShares_ShouldDeleteAllReturnedByRepository() {
        SecureShare expired1 = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().minusHours(2));
        SecureShare expired2 = buildShare(SharePermission.VIEW_ONCE, 1, 0, false,
                LocalDateTime.now().minusHours(3));

        LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
        when(shareRepository.findByExpiresAtBeforeAndIsRevokedFalse(cutoff))
                .thenReturn(List.of(expired1, expired2));

        int deleted = expirationService.deleteExpiredShares(cutoff);

        assertThat(deleted).isEqualTo(2);
        verify(shareRepository).deleteAll(List.of(expired1, expired2));
    }

    @Test
    void deleteExpiredShares_NoExpiredShares_ShouldReturn0() {
        LocalDateTime cutoff = LocalDateTime.now();
        when(shareRepository.findByExpiresAtBeforeAndIsRevokedFalse(cutoff))
                .thenReturn(Collections.emptyList());

        int deleted = expirationService.deleteExpiredShares(cutoff);

        assertThat(deleted).isZero();
        verify(shareRepository, never()).deleteAll(any());
    }

    @Test
    void deleteExpiredSharesOlderThan_ShouldComputeCutoffFromGraceHours() {
        when(shareRepository.findByExpiresAtBeforeAndIsRevokedFalse(any(LocalDateTime.class)))
                .thenReturn(Collections.emptyList());

        expirationService.deleteExpiredSharesOlderThan(24);

        ArgumentCaptor<LocalDateTime> cutoffCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(shareRepository).findByExpiresAtBeforeAndIsRevokedFalse(cutoffCaptor.capture());

        // Cutoff should be approximately 24 hours ago
        LocalDateTime captured = cutoffCaptor.getValue();
        assertThat(captured).isBefore(LocalDateTime.now().minusHours(23));
        assertThat(captured).isAfter(LocalDateTime.now().minusHours(25));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private SecureShare buildShare(SharePermission permission, int maxViews, int viewCount,
                                    boolean revoked, LocalDateTime expiresAt) {
        return SecureShare.builder()
                .id(1L)
                .vaultEntry(netflixEntry)
                .owner(alice)
                .shareToken("tok-" + System.nanoTime())
                .encryptedPassword("enc")
                .encryptionIv("iv")
                .permission(permission)
                .maxViews(maxViews)
                .viewCount(viewCount)
                .isRevoked(revoked)
                .expiresAt(expiresAt)
                .build();
    }
}
