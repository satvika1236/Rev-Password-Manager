package com.revature.passwordmanager.service.sharing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class ShareEncryptionServiceTest {

    private ShareEncryptionService service;

    @BeforeEach
    void setUp() {
        service = new ShareEncryptionService();
    }

    // ── encrypt ───────────────────────────────────────────────────────────────

    @Test
    void encrypt_ShouldReturnNonNullResult() {
        ShareEncryptionService.ShareEncryptionResult result = service.encrypt("mypassword");
        assertNotNull(result);
        assertNotNull(result.getEncryptedData());
        assertNotNull(result.getIv());
        assertNotNull(result.getKeyBase64());
    }

    @Test
    void encrypt_ShouldReturnValidBase64Fields() {
        ShareEncryptionService.ShareEncryptionResult result = service.encrypt("TestPassword123!");
        assertDoesNotThrow(() -> Base64.getDecoder().decode(result.getEncryptedData()));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(result.getIv()));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(result.getKeyBase64()));
    }

    @Test
    void encrypt_ShouldProduceAES256Key() {
        ShareEncryptionService.ShareEncryptionResult result = service.encrypt("secret");
        byte[] keyBytes = Base64.getDecoder().decode(result.getKeyBase64());
        assertEquals(32, keyBytes.length, "AES-256 key must be 32 bytes");
    }

    @Test
    void encrypt_ShouldProduceGcmIv() {
        ShareEncryptionService.ShareEncryptionResult result = service.encrypt("secret");
        byte[] iv = Base64.getDecoder().decode(result.getIv());
        assertEquals(12, iv.length, "GCM IV must be 12 bytes");
    }

    @Test
    void encrypt_ShouldProduceDifferentCiphertextEachTime() {
        String plaintext = "SamePassword1!";
        ShareEncryptionService.ShareEncryptionResult r1 = service.encrypt(plaintext);
        ShareEncryptionService.ShareEncryptionResult r2 = service.encrypt(plaintext);
        // Different keys and IVs mean different ciphertexts
        assertNotEquals(r1.getEncryptedData(), r2.getEncryptedData());
        assertNotEquals(r1.getKeyBase64(), r2.getKeyBase64());
        assertNotEquals(r1.getIv(), r2.getIv());
    }

    @Test
    void encrypt_CiphertextShouldDifferFromPlaintext() {
        ShareEncryptionService.ShareEncryptionResult result = service.encrypt("password");
        assertNotEquals("password", result.getEncryptedData());
    }

    // ── decrypt ───────────────────────────────────────────────────────────────

    @Test
    void decrypt_ShouldRecoverOriginalPlaintext() {
        String original = "MySecretPass!123";
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt(original);
        String recovered = service.decrypt(enc.getEncryptedData(), enc.getIv(), enc.getKeyBase64());
        assertEquals(original, recovered);
    }

    @Test
    void decrypt_SpecialCharacters_ShouldRoundTrip() {
        String original = "P@$$w0rd!#%^&*()_+{}|:<>?";
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt(original);
        assertEquals(original, service.decrypt(enc.getEncryptedData(), enc.getIv(), enc.getKeyBase64()));
    }

    @Test
    void decrypt_Unicode_ShouldRoundTrip() {
        String original = "\u5bc6\u7801123\u30d1\u30b9\u30ef\u30fc\u30c9";
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt(original);
        assertEquals(original, service.decrypt(enc.getEncryptedData(), enc.getIv(), enc.getKeyBase64()));
    }

    @Test
    void decrypt_EmptyString_ShouldRoundTrip() {
        String original = "";
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt(original);
        assertEquals(original, service.decrypt(enc.getEncryptedData(), enc.getIv(), enc.getKeyBase64()));
    }

    @Test
    void decrypt_WrongKey_ShouldThrow() {
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt("secret");
        // Generate a different key by encrypting something else
        ShareEncryptionService.ShareEncryptionResult other = service.encrypt("other");
        assertThrows(RuntimeException.class,
                () -> service.decrypt(enc.getEncryptedData(), enc.getIv(), other.getKeyBase64()));
    }

    @Test
    void decrypt_WrongIv_ShouldThrow() {
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt("secret");
        ShareEncryptionService.ShareEncryptionResult other = service.encrypt("other");
        assertThrows(RuntimeException.class,
                () -> service.decrypt(enc.getEncryptedData(), other.getIv(), enc.getKeyBase64()));
    }

    @Test
    void decrypt_TamperedCiphertext_ShouldThrow() {
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt("secret");
        // Tamper by appending a byte
        String tampered = enc.getEncryptedData() + "ZA==";
        assertThrows(RuntimeException.class,
                () -> service.decrypt(tampered, enc.getIv(), enc.getKeyBase64()));
    }

    // ── round-trip with long password ─────────────────────────────────────────

    @Test
    void encrypt_LongPassword_ShouldRoundTrip() {
        String longPass = "A".repeat(500);
        ShareEncryptionService.ShareEncryptionResult enc = service.encrypt(longPass);
        assertEquals(longPass, service.decrypt(enc.getEncryptedData(), enc.getIv(), enc.getKeyBase64()));
    }
}
