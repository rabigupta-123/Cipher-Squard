package com.sentinelmail;

import java.lang.reflect.Method;
import java.util.*;

public class Probe3 {
  static Method M;

  static Object call(String name, Class<?>[] sigs, Object... args) {
    long t0 = System.nanoTime();
    try {
      Method m = name.equals("policies") ? App.class.getDeclaredMethod(name) : App.class.getDeclaredMethod(name, sigs);
      m.setAccessible(true);
      Object r = m.invoke(null, args);
      long ms = (System.nanoTime() - t0) / 1_000_000;
      System.out.println(name + " ok " + ms + "ms");
      return r;
    } catch (Throwable t) {
      long ms = (System.nanoTime() - t0) / 1_000_000;
      Throwable c = (t instanceof java.lang.reflect.InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
      System.out.println(name + " -> THREW " + c.getClass().getName() + " after " + ms + "ms");
      return null;
    }
  }

  public static void main(String[] a) throws Exception {
    String longHost = "a".repeat(2000) + ".example.com";
    String raw = "From: victim@" + longHost + "\r\n\r\n" + "x".repeat(84000);
    System.out.println("=== analyze ===");
    String analysis = App.analyzeMessageForTests(raw);
    System.out.println("analysis length=" + analysis.length());

    call("numVal", new Class[]{String.class,String.class}, analysis, "riskScore");
    call("nestedStrVal", new Class[]{String.class,String.class,String.class}, analysis, "threatStatus", "state");
    call("strVal", new Class[]{String.class,String.class}, analysis, "threat_classification");
    call("strVal", new Class[]{String.class,String.class}, analysis, "risk_level");
    call("nestedInt", new Class[]{String.class,String.class,String.class}, analysis, "confidence", "value");
    call("nestedInt", new Class[]{String.class,String.class,String.class}, analysis, "completeness", "value");
    call("nestedInt", new Class[]{String.class,String.class,String.class}, analysis, "url_domain", "value");
    call("verdictOf", new Class[]{String.class}, analysis);
    call("confidenceLimitationsOf", new Class[]{String.class,String.class,int.class}, analysis, "LOW", 50);
    call("evidenceQualityOf", new Class[]{String.class,int.class,int.class,String.class}, analysis, 50, 60, "SUSPICIOUS");
    System.out.println("=== whyFromFindings ===");
    call("whyFromFindings", new Class[]{String.class}, analysis);
    System.out.println("=== persistIocs ===");
    Method persist = App.class.getDeclaredMethod("persistIocs", String.class);
    persist.setAccessible(true);
    try { persist.invoke(null, raw); System.out.println("persistIocs ok"); }
    catch (Throwable t) { Throwable c = (t.getCause()!=null)?t.getCause():t; System.out.println("persistIocs -> THREW " + c.getClass().getName()); }
    System.out.println("DONE");
  }
}