package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.user.UserSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSettingsRepository extends JpaRepository<UserSettings, Long> {
  Optional<UserSettings> findByUserId(Long userId);
}
