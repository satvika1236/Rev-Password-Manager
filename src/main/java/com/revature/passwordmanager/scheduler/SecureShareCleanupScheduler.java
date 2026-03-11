package com.revature.passwordmanager.scheduler;

import com.revature.passwordmanager.model.sharing.SecureShare;
import com.revature.passwordmanager.repository.SecureShareRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Gap 11 fix: scheduled cleanup of expired secure shares.
 *
 * <p>Expired shares are never automatically removed by JPA — without this
 * scheduler the {@code secure_shares} table grows indefinitely. Runs every
 * hour to delete shares that expired more than 24 hours ago, giving a brief
 * grace window in case a cleanup runs slightly after expiry.
 */
@Component
@RequiredArgsConstructor
public class SecureShareCleanupScheduler {

    private static final Logger logger = LoggerFactory.getLogger(SecureShareCleanupScheduler.class);

    private final SecureShareRepository shareRepository;

    @Scheduled(cron = "0 0 * * * ?") // Every hour at :00
    @Transactional
    public void cleanupExpiredShares() {
        // Delete shares that expired more than 24 hours ago
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        List<SecureShare> expired = shareRepository.findByExpiresAtBeforeAndIsRevokedFalse(cutoff);

        if (!expired.isEmpty()) {
            shareRepository.deleteAll(expired);
            logger.info("Cleaned up {} expired secure share(s) older than {}.", expired.size(), cutoff);
        }
    }
}
