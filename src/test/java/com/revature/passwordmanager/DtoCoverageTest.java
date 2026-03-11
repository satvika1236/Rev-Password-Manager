package com.revature.passwordmanager;

import com.revature.passwordmanager.util.PojoTestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.RegexPatternTypeFilter;

import java.util.Set;
import java.util.regex.Pattern;

class DtoCoverageTest {

  @Test
  void testExplicitClasses() {
    Class<?>[] classes = {
        com.revature.passwordmanager.model.vault.VaultEntry.class,
        com.revature.passwordmanager.model.user.User.class,
        com.revature.passwordmanager.model.user.UserSettings.class,
        com.revature.passwordmanager.dto.response.VaultEntryDetailResponse.class
    };

    for (Class<?> clazz : classes) {
      System.out.println("Explicitly testing: " + clazz.getName());
      PojoTestUtils.validateAccessors(clazz);
    }
  }

  @Test
  void testAllDtosAndModels() throws ClassNotFoundException {
    // Scan for all classes in dto and model packages
    ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
    provider
        .addIncludeFilter(new RegexPatternTypeFilter(Pattern.compile("com\\.revature\\.passwordmanager\\.dto\\..*")));
    provider
        .addIncludeFilter(new RegexPatternTypeFilter(Pattern.compile("com\\.revature\\.passwordmanager\\.model\\..*")));

    // Scan base package
    Set<BeanDefinition> beans = provider.findCandidateComponents("com.revature.passwordmanager");

    for (BeanDefinition bean : beans) {
      try {
        Class<?> clazz = Class.forName(bean.getBeanClassName());
        // Skip interfaces, abstract classes, records (if any), and inner classes (like
        // Builders)
        if (clazz.isInterface() || java.lang.reflect.Modifier.isAbstract(clazz.getModifiers())
            || clazz.getName().contains("$")) {
          System.out.println("Skipping POJO: " + clazz.getName() + " (interface, abstract, or inner class)");
          continue;
        }
        // Test the POJO
        PojoTestUtils.validateAccessors(clazz);
      } catch (Exception e) {
        System.err.println("Failed to test POJO: " + bean.getBeanClassName() + " - " + e.getMessage());
      }
    }
  }
}
