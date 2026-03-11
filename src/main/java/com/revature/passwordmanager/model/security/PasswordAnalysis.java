package com.revature.passwordmanager.model.security;

import com.revature.passwordmanager.model.vault.VaultEntry;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "password_analysis")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordAnalysis {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @OneToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "vault_entry_id", nullable = false, unique = true)
  private VaultEntry vaultEntry;

  @Column(name = "strength_score")
  private int strengthScore;

  @Column(name = "is_reused")
  private boolean isReused;

  @Column(name = "issues", length = 1000)
  @Convert(converter = StringListConverter.class)
  private List<String> issues;

  @Column(name = "last_analyzed", nullable = false)
  private LocalDateTime lastAnalyzed;
}
