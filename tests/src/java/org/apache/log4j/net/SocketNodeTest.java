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

import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Hashtable;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link SocketNode}, which reads the logging events received by
 * SocketServer and SimpleSocketServer.
 *
 * CVE-2023-26464: a logging event carrying deeply nested hash-based
 * collections must be refused instead of tying up the node computing
 * hash codes.
 */
public class SocketNodeTest extends TestCase {

    /** Maximum time to wait for the socket node, in milliseconds. */
    private static final int TIMEOUT = 10000;

    private ServerSocket serverSocket;
    private Socket client;
    private ObjectOutputStream oos;
    private VectorAppender appender;
    private Thread nodeThread;

    /**
     *  Create new instance.
     */
    public SocketNodeTest(final String testName) {
        super(testName);
    }

    /* JUnit's setUp and tearDown */

    protected void setUp() throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        appender = new VectorAppender();
        hierarchy.getRootLogger().addAppender(appender);

        serverSocket = new ServerSocket(0);
        client = new Socket("localhost", serverSocket.getLocalPort());
        Socket accepted = serverSocket.accept();
        // SocketNode reads the stream header when it is created
        oos = new ObjectOutputStream(client.getOutputStream());
        oos.flush();

        nodeThread = new Thread(new SocketNode(accepted, hierarchy));
        nodeThread.setDaemon(true);
        nodeThread.start();
    }

    protected void tearDown() throws Exception {
        client.close();
        serverSocket.close();
        LogManager.resetConfiguration();
    }

    /* Tests */

    /**
     * CVE-2023-26464: an event whose MDC holds deeply nested HashSets
     * must be refused and the connection dropped.
     */
    public void testDropsEventWithDeeplyNestedCollections() throws Exception {
        Hashtable properties = new Hashtable();
        properties.put("payload",
            HardenedObjectInputStreamTest.createNestedHashSetPayload(
                HardenedObjectInputStreamTest.ATTACK_DEPTH));

        try {
            oos.writeObject(createEvent("nested collections", properties));
            oos.flush();
        } catch (SocketException e) {
            // the node closed the connection while the payload was still
            // being written
        }

        nodeThread.join(TIMEOUT);
        assertFalse("socket node is still processing the payload",
                    nodeThread.isAlive());
        assertEquals(0, appender.getVector().size());
    }

    /**
     * The collection limit applies per event: many regular events with
     * MDC properties sent over a single connection are all logged.
     */
    public void testAcceptsManyEventsOnOneConnection() throws Exception {
        int events = 20;
        for (int i = 0; i < events; i++) {
            Vector roles = new Vector();
            roles.addElement("user");
            roles.addElement("admin");
            Hashtable properties = new Hashtable();
            properties.put("roles", roles);
            oos.writeObject(createEvent("event " + i, properties));
            // like SocketAppender, reset the stream after each event
            oos.reset();
        }
        oos.close();

        nodeThread.join(TIMEOUT);
        assertFalse("socket node did not finish reading the events",
                    nodeThread.isAlive());
        Vector received = appender.getVector();
        assertEquals(events, received.size());
        for (int i = 0; i < events; i++) {
            LoggingEvent event = (LoggingEvent) received.elementAt(i);
            assertEquals("event " + i, event.getRenderedMessage());
            Vector roles = (Vector) event.getMDC("roles");
            assertEquals(2, roles.size());
            assertEquals("admin", roles.elementAt(1));
        }
    }

    /* Helpers */

    private static LoggingEvent createEvent(final String message,
                                            final Hashtable properties) {
        return new LoggingEvent(Logger.class.getName(),
            Logger.getLogger(SocketNodeTest.class),
            System.currentTimeMillis(), Level.INFO, message,
            "main", null, null, null, properties);
    }
}
