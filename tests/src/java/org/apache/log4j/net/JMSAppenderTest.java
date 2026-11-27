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

package org.apache.log4j.net;

import junit.framework.TestCase;

import org.apache.log4j.VectorErrorHandler;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Hashtable;
import java.util.Vector;

import javax.jms.TopicConnectionFactory;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;


/**
 *    Tests that JMSAppender only resolves JNDI names in the java: namespace
 *    so that attacker supplied binding names such as ldap:// or rmi:// URLs
 *    can not trigger remote JNDI lookups (CVE-2021-4104).
 *
 * */
public class JMSAppenderTest extends TestCase {

  private static final String JAVA_TCF_NAME =
    "java:comp/env/jms/TopicConnectionFactory";

  private static final String[] REMOTE_NAMES = new String[] {
    "ldap://127.0.0.1:1389/Exploit",
    "ldaps://127.0.0.1:1636/Exploit",
    "rmi://127.0.0.1:1099/Exploit",
    "dns://127.0.0.1/Exploit",
    "iiop://127.0.0.1/Exploit",
    "corbaname:iiop:127.0.0.1#Exploit"
  };

  /**
   * Handler of the context returned by RecordingContextFactory.
   */
  private static RecordingContextHandler factoryHandler;

  /**
   * Create new instance of JMSAppenderTest.
   * @param testName test name
   */
  public JMSAppenderTest(final String testName) {
    super(testName);
  }

  public void tearDown() {
    factoryHandler = null;
  }

  /**
   * lookup must refuse names outside of the java: namespace without
   * ever passing them to the JNDI context.
   */
  public void testLookupRejectsNonJavaNamespace() {
    JMSAppender appender = new JMSAppender();
    for (int i = 0; i < REMOTE_NAMES.length; i++) {
      RecordingContextHandler handler =
        new RecordingContextHandler(new Object());
      try {
        appender.lookup(handler.newContext(), REMOTE_NAMES[i]);
        fail("lookup of " + REMOTE_NAMES[i] + " should have been refused");
      } catch (NamingException e) {
        assertEquals(JNDIUtil.RESTRICTION_MSG + REMOTE_NAMES[i],
                     e.getMessage());
      }
      assertEquals("context was queried for " + REMOTE_NAMES[i],
                   0, handler.lookups.size());
    }
  }

  /**
   * Names in the java: namespace are still looked up.
   */
  public void testLookupAllowsJavaNamespace() throws NamingException {
    Object bound = new Object();
    RecordingContextHandler handler = new RecordingContextHandler(bound);
    JMSAppender appender = new JMSAppender();
    assertSame(bound, appender.lookup(handler.newContext(), JAVA_TCF_NAME));
    assertEquals(1, handler.lookups.size());
    assertEquals(JAVA_TCF_NAME, handler.lookups.elementAt(0));
  }

  /**
   * An unbound java: name is reported as a NamingException.
   */
  public void testLookupReportsMissingName() {
    RecordingContextHandler handler = new RecordingContextHandler(null);
    JMSAppender appender = new JMSAppender();
    try {
      appender.lookup(handler.newContext(), "java:comp/env/jms/Missing");
      fail("lookup of an unbound name should fail");
    } catch (NamingException e) {
      assertEquals("Could not find name [java:comp/env/jms/Missing].",
                   e.getMessage());
    }
  }

  /**
   * A remote TopicConnectionFactoryBindingName set through the appender
   * configuration must be refused by activateOptions.
   */
  public void testActivateOptionsRejectsRemoteTopicConnectionFactoryName() {
    String remoteName = "ldap://127.0.0.1:1/Exploit";
    JMSAppender appender = new JMSAppender();
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setTopicConnectionFactoryBindingName(remoteName);
    appender.setTopicBindingName("ldap://127.0.0.1:1/Topic");
    appender.activateOptions();

    assertEquals(1, errorHandler.size());
    Exception e = errorHandler.getException(0);
    assertTrue(e instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + remoteName, e.getMessage());
  }

  /**
   * A remote TopicBindingName must be refused by activateOptions even when
   * the topic connection factory is legitimately bound under java:.
   */
  public void testActivateOptionsRejectsRemoteTopicName() {
    String remoteName = "ldap://127.0.0.1:1/Topic";
    StubHandler jms = new StubHandler();
    Object tcf = Proxy.newProxyInstance(
      JMSAppenderTest.class.getClassLoader(),
      new Class[] { TopicConnectionFactory.class }, jms);
    factoryHandler = new RecordingContextHandler(tcf);

    JMSAppender appender = new JMSAppender();
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setInitialContextFactoryName(
      RecordingContextFactory.class.getName());
    appender.setProviderURL("unused");
    appender.setTopicConnectionFactoryBindingName(JAVA_TCF_NAME);
    appender.setTopicBindingName(remoteName);
    appender.activateOptions();

    assertEquals(1, errorHandler.size());
    Exception e = errorHandler.getException(0);
    assertTrue(e instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + remoteName, e.getMessage());
    assertEquals(1, factoryHandler.lookups.size());
    assertEquals(JAVA_TCF_NAME, factoryHandler.lookups.elementAt(0));
  }

  /**
   * InitialContextFactory handing out the context of factoryHandler.
   */
  public static class RecordingContextFactory
    implements InitialContextFactory {
    public Context getInitialContext(final Hashtable environment) {
      return factoryHandler.newContext();
    }
  }

  /**
   * Answers Object methods of a dynamic proxy, or returns null.
   */
  private static Object invokeObjectMethod(final Object proxy,
                                           final Method method,
                                           final Object[] args) {
    String name = method.getName();
    if ("equals".equals(name)) {
      return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
    }
    if ("hashCode".equals(name)) {
      return new Integer(System.identityHashCode(proxy));
    }
    if ("toString".equals(name)) {
      return "proxy for " + proxy.getClass().getInterfaces()[0].getName();
    }
    return null;
  }

  /**
   * JNDI context that records every looked up name and answers each
   * lookup with a fixed object.
   */
  private static final class RecordingContextHandler
    implements InvocationHandler {
    final Vector lookups = new Vector();
    private final Object bound;

    RecordingContextHandler(final Object bound) {
      this.bound = bound;
    }

    Context newContext() {
      return (Context) Proxy.newProxyInstance(
        JMSAppenderTest.class.getClassLoader(),
        new Class[] { Context.class }, this);
    }

    public Object invoke(final Object proxy, final Method method,
                         final Object[] args) {
      if ("lookup".equals(method.getName())) {
        lookups.addElement(String.valueOf(args[0]));
        return bound;
      }
      return invokeObjectMethod(proxy, method, args);
    }
  }

  /**
   * JMS stub answering every interface returning method with another stub.
   */
  private static final class StubHandler implements InvocationHandler {
    public Object invoke(final Object proxy, final Method method,
                         final Object[] args) {
      Class returnType = method.getReturnType();
      if (returnType.isInterface()) {
        return Proxy.newProxyInstance(
          JMSAppenderTest.class.getClassLoader(),
          new Class[] { returnType }, this);
      }
      return invokeObjectMethod(proxy, method, args);
    }
  }
}
