/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.PropertyConfigurator;

/**
 * Regression tests for CVE-2022-23305: data carried by a logging event
 * (message, MDC values, ...) must never be interpreted as SQL by
 * JDBCAppender.
 */
public class JdbcAppenderSqlInjectionTest extends TestCase {

  private static final String URL = "jdbc:h2:mem:sql_injection_db";

  private static final String SQL =
      "insert into logs(level,message) values('%p','%m')";

  // Closing the last connection to "in-memory h2" removes the database
  // So we keep the connection during the test
  private Connection con;

  private final Logger logger =
      Logger.getLogger(JdbcAppenderSqlInjectionTest.class);

  public JdbcAppenderSqlInjectionTest(final String name) {
    super(name);
  }

  protected void setUp() throws Exception {
    Class.forName("org.h2.Driver");
    con = DriverManager.getConnection(URL);
    Statement st = con.createStatement();
    try {
      st.execute("create table logs(level varchar(100),message varchar(200))");
      st.execute("create table secrets(secret varchar(100))");
      st.execute("insert into secrets(secret) values('TOP-SECRET')");
    } finally {
      st.close();
    }
  }

  protected void tearDown() throws Exception {
    LogManager.shutdown();
    MDC.remove("user");
    con.close();
  }

  /**
   * The message closes the quoted literal and concatenates a SQL expression.
   */
  public void testMessageIsNotEvaluatedAsSqlExpression() throws SQLException {
    configure(SQL, 1);
    String payload = "' || 'INJECTED' || '";
    logger.info(payload);
    assertMessages(new String[] {payload});
  }

  /**
   * The message reads another table through a sub-query.
   */
  public void testMessageCannotReadOtherTables() throws SQLException {
    configure(SQL, 1);
    String payload = "' || (select max(secret) from secrets) || '";
    logger.info(payload);
    assertMessages(new String[] {payload});
  }

  /**
   * The message terminates the insert and appends another statement.
   */
  public void testMessageCannotRunStackedStatement() throws SQLException {
    configure(SQL, 1);
    String payload = "x'); delete from secrets; --";
    logger.info(payload);
    assertEquals("secrets must survive", 1, countRows("secrets"));
    assertMessages(new String[] {payload});
  }

  /**
   * Buffered events are inserted in a batch, which must be safe as well.
   */
  public void testBufferedMessagesAreNotEvaluatedAsSql() throws SQLException {
    configure(SQL, 2);
    String payload1 = "' || (select max(secret) from secrets) || '";
    String payload2 = "x'); delete from secrets; --";
    logger.info(payload1);
    logger.warn(payload2);
    assertEquals("secrets must survive", 1, countRows("secrets"));
    assertMessages(new String[] {payload1, payload2});
  }

  /**
   * An MDC value is attacker controlled as well; the appender is set up
   * programmatically, without calling activateOptions.
   */
  public void testMdcValueIsNotEvaluatedAsSql() throws SQLException {
    JDBCAppender appender = new JDBCAppender();
    appender.setURL(URL);
    appender.setUser("");
    appender.setPassword("");
    appender.setSql("insert into logs(level,message) values('%p','%X{user}')");
    logger.addAppender(appender);

    String payload = "' || (select max(secret) from secrets) || '";
    MDC.put("user", payload);
    logger.info("login");
    assertMessages(new String[] {payload});
  }

  private void configure(final String sql, final int bufferSize) {
    Properties props = new Properties();
    props.setProperty("log4j.rootLogger", "ALL,A");
    props.setProperty("log4j.appender.A", "org.apache.log4j.jdbc.JDBCAppender");
    props.setProperty("log4j.appender.A.URL", URL);
    props.setProperty("log4j.appender.A.driver", "org.h2.Driver");
    props.setProperty("log4j.appender.A.bufferSize", String.valueOf(bufferSize));
    props.setProperty("log4j.appender.A.user", "");
    props.setProperty("log4j.appender.A.password", "");
    props.setProperty("log4j.appender.A.layout", "org.apache.log4j.PatternLayout");
    props.setProperty("log4j.appender.A.sql", sql);
    PropertyConfigurator.configure(props);
  }

  private void assertMessages(final String[] expected) throws SQLException {
    List actual = new ArrayList();
    Statement st = con.createStatement();
    try {
      ResultSet rs = st.executeQuery("select message from logs order by message");
      while (rs.next()) {
        actual.add(rs.getString(1));
      }
      rs.close();
    } finally {
      st.close();
    }
    List sorted = new ArrayList();
    for (int i = 0; i < expected.length; i++) {
      sorted.add(expected[i]);
    }
    java.util.Collections.sort(sorted);
    assertEquals(sorted, actual);
  }

  private int countRows(final String table) throws SQLException {
    Statement st = con.createStatement();
    try {
      ResultSet rs = st.executeQuery("select count(*) from " + table);
      rs.next();
      int count = rs.getInt(1);
      rs.close();
      return count;
    } finally {
      st.close();
    }
  }
}
