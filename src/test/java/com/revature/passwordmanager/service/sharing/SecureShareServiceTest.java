package com.revature.passwordmanager.service.sharing;

import com.revature.passwordmanager.dto.request.CreateShareRequest;
import com.revature.passwordmanager.dto.response.ShareLinkResponse;
import com.revature.passwordmanager.dto.response.SharedPasswordResponse;
import com.revature.passwordmanager.exception.ResourceNotFoundException;
import com.revature.passwordmanager.model.sharing.SecureShare;
import com.revature.passwordmanager.model.sharing.SharePermission;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.model.vault.VaultEntry;
import com.revature.passwordmanager.repository.SecureShareRepository;
import com.revature.passwordmanager.repository.UserRepository;
import com.revature.passwordmanager.repository.VaultEntryRepository;
import com.revature.passwordmanager.service.email.EmailService;
import com.revature.passwordmanager.service.notification.NotificationService;
import com.revature.passwordmanager.service.security.AuditLogService;
import com.revature.passwordmanager.service.security.EncryptionService;
import com.revature.passwordmanager.util.EncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecureShareServiceTest {

    @Mock private SecureShareRepository shareRepository;
    @Mock private UserRepository userRepository;
    @Mock private VaultEntryRepository vaultEntryRepository;
    @Mock private EncryptionService encryptionService;
    @Mock private EncryptionUtil encryptionUtil;
    @Mock private ShareTokenGenerator tokenGenerator;
    @Mock private ShareEncryptionService shareEncryptionService;
    @Mock private EmailService emailService;
    @Mock private NotificationService notificationService;
    @Mock private AuditLogService auditLogService;

    @InjectMocks private SecureShareService service;

    private User owner;
    private VaultEntry entry;
    private SecretKey mockKey;

    @BeforeEach
    void setUp() {
        owner = User.builder().id(1L).username("alice").email("alice@example.com")
                .masterPasswordHash("hash").salt("salt").build();
        entry = VaultEntry.builder().id(10L).title("Netflix").username("encUser")
                .password("encPass").websiteUrl("https://netflix.com")
                .user(owner).createdAt(LocalDateTime.now()).updatedAt(LocalDateTime.now())
                .isDeleted(false).isFavorite(false).isHighlySensitive(false).build();
        mockKey = mock(SecretKey.class);
    }

    // ── createShare ───────────────────────────────────────────────────────────

    @Test
    void createShare_ValidRequest_ShouldReturnShareLink() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(vaultEntryRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("plainPassword");
        when(shareEncryptionService.encrypt("plainPassword")).thenReturn(
                ShareEncryptionService.ShareEncryptionResult.builder()
                        .encryptedData("enc==").iv("iv==").keyBase64("key==").build());
        when(tokenGenerator.generate()).thenReturn("abc123token");
        when(shareRepository.save(any())).thenAnswer(inv -> {
            SecureShare s = inv.getArgument(0);
            return SecureShare.builder().id(1L).vaultEntry(s.getVaultEntry()).owner(s.getOwner())
                    .shareToken(s.getShareToken()).encryptedPassword(s.getEncryptedPassword())
                    .encryptionIv(s.getEncryptionIv()).expiresAt(s.getExpiresAt())
                    .permission(s.getPermission()).maxViews(s.getMaxViews()).viewCount(0)
                    .isRevoked(false).createdAt(LocalDateTime.now()).build();
        });

        // stub userRepository.findByEmail for in-app notification lookup (Gap 10)
        when(userRepository.findByEmail("bob@example.com")).thenReturn(Optional.empty());

        CreateShareRequest request = CreateShareRequest.builder()
                .vaultEntryId(10L).recipientEmail("bob@example.com")
                .expiryHours(24).maxViews(1).permission("VIEW_ONCE").build();

        ShareLinkResponse result = service.createShare("alice", request);

        assertNotNull(result);
        assertEquals(1L, result.getShareId());
        assertEquals("abc123token", result.getShareToken());
        assertEquals("/api/shares/abc123token", result.getShareUrl());
        assertEquals("key==", result.getEncryptionKey());
        assertEquals("Netflix", result.getVaultEntryTitle());
        assertEquals("VIEW_ONCE", result.getPermission());
        assertFalse(result.isRevoked());
    }

    @Test
    void createShare_UnknownPermission_ShouldDefaultToViewOnce() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(vaultEntryRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("plainPassword");
        when(shareEncryptionService.encrypt(anyString())).thenReturn(
                ShareEncryptionService.ShareEncryptionResult.builder()
                        .encryptedData("enc==").iv("iv==").keyBase64("key==").build());
        when(tokenGenerator.generate()).thenReturn("tok1");
        when(shareRepository.save(any())).thenAnswer(inv -> {
            SecureShare s = inv.getArgument(0);
            return SecureShare.builder().id(2L).vaultEntry(s.getVaultEntry()).owner(s.getOwner())
                    .shareToken(s.getShareToken()).encryptedPassword(s.getEncryptedPassword())
                    .encryptionIv(s.getEncryptionIv()).expiresAt(s.getExpiresAt())
                    .permission(s.getPermission()).maxViews(s.getMaxViews()).viewCount(0)
                    .isRevoked(false).createdAt(LocalDateTime.now()).build();
        });

        CreateShareRequest request = CreateShareRequest.builder()
                .vaultEntryId(10L).expiryHours(24).maxViews(1).permission("INVALID_PERM").build();

        ShareLinkResponse result = service.createShare("alice", request);
        assertEquals("VIEW_ONCE", result.getPermission());
    }

    @Test
    void createShare_TemporaryAccess_ShouldSetMaxViewsToMaxInt() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(vaultEntryRepository.findByIdAndUserId(10L, 1L)).thenReturn(Optional.of(entry));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("pass");
        when(shareEncryptionService.encrypt(anyString())).thenReturn(
                ShareEncryptionService.ShareEncryptionResult.builder()
                        .encryptedData("e").iv("i").keyBase64("k").build());
        when(tokenGenerator.generate()).thenReturn("tok2");
        ArgumentCaptor<SecureShare> captor = ArgumentCaptor.forClass(SecureShare.class);
        when(shareRepository.save(captor.capture())).thenAnswer(inv -> {
            SecureShare s = inv.getArgument(0);
            return SecureShare.builder().id(3L).vaultEntry(s.getVaultEntry()).owner(s.getOwner())
                    .shareToken(s.getShareToken()).encryptedPassword(s.getEncryptedPassword())
                    .encryptionIv(s.getEncryptionIv()).expiresAt(s.getExpiresAt())
                    .permission(s.getPermission()).maxViews(s.getMaxViews()).viewCount(0)
                    .isRevoked(false).createdAt(LocalDateTime.now()).build();
        });

        service.createShare("alice", CreateShareRequest.builder()
                .vaultEntryId(10L).expiryHours(48).maxViews(1).permission("TEMPORARY_ACCESS").build());

        assertEquals(Integer.MAX_VALUE, captor.getValue().getMaxViews());
    }

    @Test
    void createShare_EntryNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(vaultEntryRepository.findByIdAndUserId(999L, 1L)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> service.createShare("alice", CreateShareRequest.builder()
                        .vaultEntryId(999L).expiryHours(24).maxViews(1).permission("VIEW_ONCE").build()));
    }

    @Test
    void createShare_UserNotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("unknown"))
                .thenThrow(new ResourceNotFoundException("User not found"));

        assertThrows(ResourceNotFoundException.class,
                () -> service.createShare("unknown", CreateShareRequest.builder()
                        .vaultEntryId(10L).expiryHours(24).maxViews(1).permission("VIEW_ONCE").build()));
    }

    // ── getSharedPassword ─────────────────────────────────────────────────────

    @Test
    void getSharedPassword_ValidToken_ShouldReturnAndIncrementView() {
        SecureShare share = buildShare("tok1", false, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(shareRepository.findByShareToken("tok1")).thenReturn(Optional.of(share));
        when(shareRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("user@example.com");

        SharedPasswordResponse result = service.getSharedPassword("tok1");

        assertNotNull(result);
        assertEquals("Netflix", result.getTitle());
        assertEquals("enc==", result.getEncryptedPassword());
        assertEquals("iv==", result.getEncryptionIv());
        assertEquals("https://netflix.com", result.getWebsiteUrl());
        assertEquals("VIEW_ONCE", result.getPermission());
        assertEquals("alice", result.getSharedBy());
        assertEquals(0, result.getViewsRemaining()); // 1 view used, 1 max => 0 remaining
        verify(shareRepository).save(argThat(s -> s.getViewCount() == 1));
    }

    @Test
    void getSharedPassword_TokenNotFound_ShouldThrow() {
        when(shareRepository.findByShareToken("bad")).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> service.getSharedPassword("bad"));
    }

    @Test
    void getSharedPassword_RevokedShare_ShouldThrowIllegalState() {
        SecureShare share = buildShare("tok2", true, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(shareRepository.findByShareToken("tok2")).thenReturn(Optional.of(share));
        assertThrows(IllegalStateException.class, () -> service.getSharedPassword("tok2"));
    }

    @Test
    void getSharedPassword_ExpiredShare_ShouldThrowIllegalState() {
        SecureShare share = buildShare("tok3", false, LocalDateTime.now().minusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(shareRepository.findByShareToken("tok3")).thenReturn(Optional.of(share));
        assertThrows(IllegalStateException.class, () -> service.getSharedPassword("tok3"));
    }

    @Test
    void getSharedPassword_ViewLimitReached_ShouldThrowIllegalState() {
        SecureShare share = buildShare("tok4", false, LocalDateTime.now().plusHours(1), 1, 1,
                SharePermission.VIEW_ONCE);
        when(shareRepository.findByShareToken("tok4")).thenReturn(Optional.of(share));
        assertThrows(IllegalStateException.class, () -> service.getSharedPassword("tok4"));
    }

    @Test
    void getSharedPassword_TemporaryAccess_ViewsRemainingShouldBeMaxInt() {
        SecureShare share = buildShare("tok5", false, LocalDateTime.now().plusHours(1), 0,
                Integer.MAX_VALUE, SharePermission.TEMPORARY_ACCESS);
        when(shareRepository.findByShareToken("tok5")).thenReturn(Optional.of(share));
        when(shareRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(encryptionUtil.deriveKey(anyString(), anyString())).thenReturn(mockKey);
        when(encryptionService.decrypt(anyString(), eq(mockKey))).thenReturn("user@example.com");

        SharedPasswordResponse result = service.getSharedPassword("tok5");
        assertEquals(Integer.MAX_VALUE, result.getViewsRemaining());
    }

    // ── getActiveShares ───────────────────────────────────────────────────────

    @Test
    void getActiveShares_ShouldReturnList() {
        SecureShare share = buildShare("tok1", false, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findActiveSharesByOwnerId(eq(1L), any())).thenReturn(List.of(share));

        List<ShareLinkResponse> result = service.getActiveShares("alice");
        assertEquals(1, result.size());
        assertEquals("tok1", result.get(0).getShareToken());
        assertNull(result.get(0).getEncryptionKey()); // key not returned on list
    }

    @Test
    void getActiveShares_Empty_ShouldReturnEmptyList() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findActiveSharesByOwnerId(eq(1L), any())).thenReturn(Collections.emptyList());

        assertTrue(service.getActiveShares("alice").isEmpty());
    }

    // ── revokeShare ───────────────────────────────────────────────────────────

    @Test
    void revokeShare_ShouldSetRevokedTrue() {
        SecureShare share = buildShare("tok1", false, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findById(1L)).thenReturn(Optional.of(share));
        when(shareRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ShareLinkResponse result = service.revokeShare("alice", 1L);
        assertTrue(result.isRevoked());

        ArgumentCaptor<SecureShare> captor = ArgumentCaptor.forClass(SecureShare.class);
        verify(shareRepository).save(captor.capture());
        assertTrue(captor.getValue().isRevoked());
    }

    @Test
    void revokeShare_NotFound_ShouldThrow() {
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findById(99L)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> service.revokeShare("alice", 99L));
    }

    @Test
    void revokeShare_WrongOwner_ShouldThrow() {
        User otherUser = User.builder().id(99L).username("charlie").email("c@c.com")
                .masterPasswordHash("h").salt("s").build();
        SecureShare share = buildShare("tok1", false, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        share.setOwner(otherUser);

        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findById(1L)).thenReturn(Optional.of(share));

        assertThrows(IllegalArgumentException.class, () -> service.revokeShare("alice", 1L));
    }

    // ── getReceivedShares ─────────────────────────────────────────────────────

    @Test
    void getReceivedShares_ShouldReturnSharesForUserEmail() {
        SecureShare share = buildShare("tok1", false, LocalDateTime.now().plusHours(1), 0, 1,
                SharePermission.VIEW_ONCE);
        when(userRepository.findByUsernameOrThrow("alice")).thenReturn(owner);
        when(shareRepository.findActiveSharesForRecipient(eq("alice@example.com"), any()))
                .thenReturn(List.of(share));

        List<ShareLinkResponse> result = service.getReceivedShares("alice");
        assertEquals(1, result.size());
    }

    @Test
    void getReceivedShares_UserWithNoEmail_ShouldReturnEmpty() {
        User noEmailUser = User.builder().id(2L).username("bob").email(null)
                .masterPasswordHash("h").salt("s").build();
        when(userRepository.findByUsernameOrThrow("bob")).thenReturn(noEmailUser);

        assertTrue(service.getReceivedShares("bob").isEmpty());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private SecureShare buildShare(String token, boolean revoked, LocalDateTime expiresAt,
                                   int viewCount, int maxViews, SharePermission permission) {
        return SecureShare.builder()
                .id(1L).vaultEntry(entry).owner(owner)
                .shareToken(token).encryptedPassword("enc==").encryptionIv("iv==")
                .expiresAt(expiresAt).viewCount(viewCount).maxViews(maxViews)
                .permission(permission).isRevoked(revoked).createdAt(LocalDateTime.now())
                .build();
    }
}
