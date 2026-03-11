package com.revature.passwordmanager.service.analytics;

import com.revature.passwordmanager.dto.response.HeatmapResponse;
import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.user.User;
import com.revature.passwordmanager.repository.AuditLogRepository;
import com.revature.passwordmanager.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.DayOfWeek;
import java.time.format.TextStyle;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AccessHeatmapService {

  private final AuditLogRepository auditLogRepository;
  private final UserRepository userRepository;

  @Transactional(readOnly = true)
  public HeatmapResponse getAccessHeatmap(String username) {
    User user = userRepository.findByUsernameOrThrow(username);

    LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
    List<AuditLog> logs = auditLogRepository.findByUserIdAndTimestampAfter(user.getId(), thirtyDaysAgo);

    int[] hourlyCounts = new int[24];
    int[] dailyCounts = new int[7];

    for (AuditLog log : logs) {
      LocalDateTime ts = log.getTimestamp();
      hourlyCounts[ts.getHour()]++;

      DayOfWeek day = ts.getDayOfWeek();

      int dayIndex = (day.getValue() % 7);
      dailyCounts[dayIndex]++;
    }

    List<Integer> hourlyList = new ArrayList<>();
    for (int c : hourlyCounts)
      hourlyList.add(c);

    List<Integer> dailyList = new ArrayList<>();
    for (int c : dailyCounts)
      dailyList.add(c);

    int peakHour = -1;
    int maxHourCount = 0;
    for (int i = 0; i < 24; i++) {
      if (hourlyCounts[i] > maxHourCount) {
        maxHourCount = hourlyCounts[i];
        peakHour = i;
      }
    }

    int peakDayIndex = -1;
    int maxDayCount = 0;
    for (int i = 0; i < 7; i++) {
      if (dailyCounts[i] > maxDayCount) {
        maxDayCount = dailyCounts[i];
        peakDayIndex = i;
      }
    }

    String peakDayName = "";
    if (peakDayIndex != -1) {

      int javaDayValue = (peakDayIndex == 0) ? 7 : peakDayIndex;
      peakDayName = DayOfWeek.of(javaDayValue).getDisplayName(TextStyle.FULL, Locale.getDefault());
    }

    return HeatmapResponse.builder()
        .accessByHour(hourlyList)
        .accessByDay(dailyList)
        .peakHour(peakHour)
        .peakDay(peakDayName)
        .totalAccesses(logs.size())
        .period("LAST_30_DAYS")
        .build();
  }
}
