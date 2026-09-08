package com.sentinelmail;

import java.lang.reflect.Method;

public class Probe {
  public static void main(String[] a) throws Exception {
    String longHost = "a".repeat(2000) + ".example.com";
    String raw = "From: victim@" + longHost + "\r\n\r\n" + "x".repeat(84000);
    Method persist = App.class.getDeclaredMethod("persistIocs", String.class);
    persist.setAccessible(true);
    Method decision = App.class.getDeclaredMethod("decisionOf", String.class, String.class);
    decision.setAccessible(true);
    long t0 = System.currentTimeMillis();
    try {
      String analysis = App.analyzeMessageForTests(raw);
      long t1 = System.currentTimeMillis();
      persist.invoke(null, raw);
      long t2 = System.currentTimeMillis();
      decision.invoke(null, analysis, "paste");
      long t3 = System.currentTimeMillis();
      System.out.println("analyze="+(t1-t0)+"ms persistIocs="+(t2-t1)+"ms decisionOf="+(t3-t2)+"ms");
    } catch (Throwable t) { System.out.println("THREW " + t.getClass().getName()); t.printStackTrace(System.out); }
  }
}