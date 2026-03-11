package com.revature.passwordmanager.dto.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ReceiveShareRequest}.
 *
 * <p>Gap closure: {@code ReceiveShareRequest} was proposed in the Feature 35 spec
 * but was not implemented because the retrieval endpoint uses a path variable for
 * the token and requires no mandatory body. The DTO is implemented for
 * forward-compatibility with optional fields for recipient context.</p>
 */
class ReceiveShareRequestTest {

    @Test
    void builder_AllFieldsNull_ShouldBeValid() {
        ReceiveShareRequest req = ReceiveShareRequest.builder().build();

        assertThat(req.getRecipientNote()).isNull();
        assertThat(req.getRecipientEmail()).isNull();
    }

    @Test
    void builder_AllFieldsSet_ShouldPopulateCorrectly() {
        ReceiveShareRequest req = ReceiveShareRequest.builder()
                .recipientNote("Accessing for team setup")
                .recipientEmail("bob@example.com")
                .build();

        assertThat(req.getRecipientNote()).isEqualTo("Accessing for team setup");
        assertThat(req.getRecipientEmail()).isEqualTo("bob@example.com");
    }

    @Test
    void noArgsConstructor_ShouldCreateEmptyInstance() {
        ReceiveShareRequest req = new ReceiveShareRequest();

        assertThat(req.getRecipientNote()).isNull();
        assertThat(req.getRecipientEmail()).isNull();
    }

    @Test
    void allArgsConstructor_ShouldPopulateFields() {
        ReceiveShareRequest req = new ReceiveShareRequest("Team access", "team@example.com");

        assertThat(req.getRecipientNote()).isEqualTo("Team access");
        assertThat(req.getRecipientEmail()).isEqualTo("team@example.com");
    }

    @Test
    void setter_ShouldUpdateField() {
        ReceiveShareRequest req = new ReceiveShareRequest();
        req.setRecipientEmail("updated@example.com");
        req.setRecipientNote("Updated note");

        assertThat(req.getRecipientEmail()).isEqualTo("updated@example.com");
        assertThat(req.getRecipientNote()).isEqualTo("Updated note");
    }

    @Test
    void twoRequestsWithSameFields_ShouldBeEqual() {
        ReceiveShareRequest r1 = new ReceiveShareRequest("note", "email@test.com");
        ReceiveShareRequest r2 = new ReceiveShareRequest("note", "email@test.com");

        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void twoRequestsWithDifferentFields_ShouldNotBeEqual() {
        ReceiveShareRequest r1 = new ReceiveShareRequest("note1", "a@test.com");
        ReceiveShareRequest r2 = new ReceiveShareRequest("note2", "b@test.com");

        assertThat(r1).isNotEqualTo(r2);
    }

    @Test
    void toString_ShouldContainFields() {
        ReceiveShareRequest req = new ReceiveShareRequest("my note", "user@example.com");

        assertThat(req.toString())
                .contains("my note")
                .contains("user@example.com");
    }
}
