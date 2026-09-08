package com.sentinelmail;

import java.util.regex.*;
import java.lang.reflect.Field;

public class MiniProbe {
  static void time(String name, java.util.function.Supplier<Object> fn) {
    long t0 = System.nanoTime();
    Throwable got = null;
    Object r = null;
    try { r = fn.get(); } catch (Throwable t) { got = t; }
    long ms = (System.nanoTime() - t0) / 1_000_000;
    if (got != null) {
      System.out.println(name + " -> THREW " + got.getClass().getName() + " ms=" + ms);
      for (StackTraceElement e : got.getStackTrace()) {
        System.out.println("    " + e);
        if (e.getClassName().startsWith("com.sentinelmail")) break;
      }
    } else {
      Object size = (r instanceof java.util.Collection) ? ((java.util.Collection<?>) r).size() : r;
      System.out.println(name + " -> ok ms=" + ms + " result=" + size);
    }
  }

  public static void main(String[] a) throws Exception {
    String longHost = "a".repeat(2000) + ".example.com";
    String raw = "From: victim@" + longHost + "\r\n\r\n" + "x".repeat(84000);

    Field[] fs = App.class.getDeclaredFields();
    Class<?> clazz = App.class;
    Field url = clazz.getDeclaredField("URL");
    url.setAccessible(true);
    Pattern URL = (Pattern) url.get(null);
    Field email = clazz.getDeclaredField("EMAIL"); email.setAccessible(true); Pattern EMAIL = (Pattern) email.get(null);
    Field ip4 = clazz.getDeclaredField("IPV4"); ip4.setAccessible(true); Pattern IPV4 = (Pattern) ip4.get(null);
    Field ip6 = clazz.getDeclaredField("IPV6"); ip6.setAccessible(true); Pattern IPV6 = (Pattern) ip6.get(null);
    Field sha = clazz.getDeclaredField("SHA256RE"); sha.setAccessible(true); Pattern SHA256RE = (Pattern) sha.get(null);
    java.lang.reflect.Method sc = App.class.getDeclaredMethod("scanDomains", String.class);
    sc.setAccessible(true);

    System.out.println("raw length=" + raw.length());
    time("IPV4 matches", () -> { java.util.List<String> r = new java.util.ArrayList<>(); java.util.regex.Matcher m = IPV4.matcher(raw); while (m.find()) r.add(m.group()); return r; });
    time("URL matches", () -> { java.util.List<String> r = new java.util.ArrayList<>(); java.util.regex.Matcher m = URL.matcher(raw); while (m.find()) r.add(m.group()); return r; });
    time("EMAIL matches", () -> { java.util.List<String> r = new java.util.ArrayList<>(); java.util.regex.Matcher m = EMAIL.matcher(raw); while (m.find()) r.add(m.group()); return r; });
    time("IPV6 matches", () -> { java.util.List<String> r = new java.util.ArrayList<>(); java.util.regex.Matcher m = IPV6.matcher(raw); while (m.find()) r.add(m.group()); return r; });
    time("SHA256RE matches", () -> { java.util.List<String> r = new java.util.ArrayList<>(); java.util.regex.Matcher m = SHA256RE.matcher(raw); while (m.find()) r.add(m.group()); return r; });

    time("scanDomains", () -> { try { return sc.invoke(null, raw); } catch (Throwable t) { throw new RuntimeException(t); } });
  }
}