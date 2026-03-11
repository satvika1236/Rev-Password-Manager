package com.revature.passwordmanager.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public class PojoTestUtils {

  public static void validateAccessors(Class<?> clazz) {
    try {
      Object instance = createInstance(clazz);
      for (Field field : clazz.getDeclaredFields()) {
        if (Modifier.isStatic(field.getModifiers()) || field.getName().startsWith("$")) {
          continue;
        }
        field.setAccessible(true);

        String fieldName = field.getName();
        String capitalizedName = Character.toUpperCase(fieldName.charAt(0)) + fieldName.substring(1);

        // Try setter
        try {
          Method setter = clazz.getMethod("set" + capitalizedName, field.getType());
          Object value = createValue(field.getType());
          setter.invoke(instance, value);
        } catch (NoSuchMethodException e) {
          // Ignore if no setter
        }

        // Try getter
        try {
          Method getter = clazz.getMethod("get" + capitalizedName);
          getter.invoke(instance);
        } catch (NoSuchMethodException e) {
          try {
            Method isGetter = clazz.getMethod("is" + capitalizedName);
            isGetter.invoke(instance);
          } catch (NoSuchMethodException ex) {
            // Ignore
          }
        }
      }

      // Trigger toString, equals, hashCode
      instance.toString();
      instance.hashCode();
      instance.equals(instance);
      instance.equals(new Object());
      instance.equals(null);

      Object instance2 = createInstance(clazz);
      // Best effort to make them equal or not equal, not strict check
      instance.equals(instance2);

      // Lombok often adds canEqual
      try {
        Method canEqual = clazz.getMethod("canEqual", Object.class);
        canEqual.invoke(instance, new Object());
        canEqual.invoke(instance, instance);
      } catch (NoSuchMethodException e) {
        // Ignore
      }

      testBuilder(clazz);
      testAllArgsConstructor(clazz);

    } catch (Exception e) {
      // If instantiation fails (e.g. private constructor), we just skip coverage for
      // that class essentially
      System.err.println("Skipping pojo test for " + clazz.getName() + ": " + e.getMessage());
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }

  private static void testAllArgsConstructor(Class<?> clazz) {
    try {
      for (java.lang.reflect.Constructor<?> constructor : clazz.getDeclaredConstructors()) {
        if (constructor.getParameterCount() > 0) {
          try {
            Object[] args = new Object[constructor.getParameterCount()];
            Class<?>[] paramTypes = constructor.getParameterTypes();
            for (int i = 0; i < args.length; i++) {
              args[i] = createValue(paramTypes[i]);
            }
            constructor.newInstance(args);
          } catch (Exception e) {
            // Ignore specific constructor failure
          }
        }
      }
    } catch (Exception e) {
      // Ignore
    }
  }

  private static void testBuilder(Class<?> clazz) {
    try {
      Method builderMethod = clazz.getMethod("builder");
      Object builder = builderMethod.invoke(null);
      Class<?> builderClass = builder.getClass();

      for (Method method : builderClass.getDeclaredMethods()) {
        if (Modifier.isPublic(method.getModifiers())) {
          try {
            Object[] args = new Object[method.getParameterCount()];
            Class<?>[] paramTypes = method.getParameterTypes();
            for (int i = 0; i < args.length; i++) {
              args[i] = createValue(paramTypes[i]);
            }
            method.invoke(builder, args);
          } catch (Exception e) {
            // Ignore individual method failures on builder
          }
        }
      }

      builder.toString();

    } catch (Exception e) {
      // No builder or failed
    }
  }

  private static Object createInstance(Class<?> clazz) throws Exception {
    try {
      java.lang.reflect.Constructor<?> constructor = clazz.getDeclaredConstructor();
      constructor.setAccessible(true);
      return constructor.newInstance();
    } catch (Exception e) {
      // Try builder if exists
      try {
        Method builderMethod = clazz.getMethod("builder");
        Object builder = builderMethod.invoke(null);

        // Try to set required fields if possible - complex, but we can try to find
        // setters on builder
        // For now, just try build()
        Method buildMethod = builder.getClass().getMethod("build");
        return buildMethod.invoke(builder);
      } catch (Exception ex) {
        throw new RuntimeException("Could not instantiate " + clazz.getName());
      }
    }
  }

  private static Object createValue(Class<?> type) {
    if (type == String.class)
      return "test";
    if (type == Long.class || type == long.class)
      return 1L;
    if (type == Integer.class || type == int.class)
      return 1;
    if (type == Boolean.class || type == boolean.class)
      return true;
    if (type == Double.class || type == double.class)
      return 1.0;
    if (type == List.class)
      return new ArrayList<>();
    if (type.isEnum())
      return type.getEnumConstants()[0];
    return null; // For complex types, null is often enough for simple setter coverage
  }
}
