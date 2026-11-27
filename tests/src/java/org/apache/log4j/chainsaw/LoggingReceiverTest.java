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
package org.apache.log4j.chainsaw;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Hashtable;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LocationInfo;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.ThrowableInformation;
import org.apache.log4j.xml.DOMConfigurator;

/**
 * Tests for {@link LoggingReceiver}, the socket receiver of Chainsaw.
 *
 * The receiver must only deserialize logging events and must refuse any
 * other class sent by a remote client (CVE-2022-23307).
 */
public class LoggingReceiverTest extends TestCase {

    /** Port used by input/xml/socketAppenderForChainsaw.xml. */
    private static final int CHAINSAW_CONFIG_PORT = 4445;

    /** Maximum time to wait for the receiver, in milliseconds. */
    private static final int TIMEOUT = 10000;

    /** Model receiving the events. */
    private MyTableModel model;

    /** Receiver under test. */
    private LoggingReceiver receiver;

    /**
     *  Create new instance.
     */
    public LoggingReceiverTest(final String testName) {
        super(testName);
    }

    /* JUnit's setUp and tearDown */

    protected void setUp() {
        Gadget.deserialized = false;
    }

    protected void tearDown() throws Exception {
        LogManager.resetConfiguration();
        if (receiver != null) {
            getServerSocket(receiver).close();
            receiver = null;
        }
        model = null;
        Gadget.deserialized = false;
    }

    /* Tests */

    /**
     * A serialized object which is not a logging event must be rejected
     * before it is instantiated.
     */
    public void testRejectsArbitraryObject() throws Exception {
        int port = startReceiver(0);

        boolean dropped = sendAndAwaitClose(port, new Gadget("direct"));

        assertFalse("untrusted class was deserialized by the receiver",
                    Gadget.deserialized);
        assertTrue("receiver did not drop the connection", dropped);
        assertEquals(0, model.getRowCount());
    }

    /**
     * An untrusted object nested inside an otherwise valid logging event
     * (here in its MDC properties) must be rejected as well.
     */
    public void testRejectsArbitraryObjectNestedInLoggingEvent()
        throws Exception {
        int port = startReceiver(0);

        Hashtable properties = new Hashtable();
        properties.put("payload", new Gadget("nested"));
        LoggingEvent event = new LoggingEvent(Logger.class.getName(),
            Logger.getLogger(LoggingReceiverTest.class),
            System.currentTimeMillis(), Level.INFO, "carrier event",
            "main", null, null, null, properties);

        boolean dropped = sendAndAwaitClose(port, event);

        assertFalse("untrusted class was deserialized by the receiver",
                    Gadget.deserialized);
        assertTrue("receiver did not drop the connection", dropped);
        assertNull(findEvent("carrier event"));
    }

    /**
     * Regular logging events must still be received and displayed.
     */
    public void testAcceptsLoggingEvent() throws Exception {
        int port = startReceiver(0);

        String message = "legitimate event";
        LoggingEvent event = new LoggingEvent(Logger.class.getName(),
            Logger.getLogger(LoggingReceiverTest.class),
            System.currentTimeMillis(), Level.WARN, message, "main",
            new ThrowableInformation(new String[] {
                "java.lang.Exception: boom",
                "\tat org.example.Foo.bar(Foo.java:42)"}),
            "ndc",
            new LocationInfo("Foo.java", "org.example.Foo", "bar", "42"),
            null);

        Socket socket = new Socket("localhost", port);
        try {
            ObjectOutputStream oos =
                new ObjectOutputStream(socket.getOutputStream());
            oos.writeObject(event);
            oos.flush();

            EventDetails details = awaitEvent(message);
            assertNotNull("logging event was not received", details);
            assertEquals(Level.WARN, details.getPriority());
            assertEquals(LoggingReceiverTest.class.getName(),
                         details.getCategoryName());
            assertEquals("ndc", details.getNDC());
            assertEquals("main", details.getThreadName());
            assertEquals("org.example.Foo.bar(Foo.java:42)",
                         details.getLocationDetails());
            assertEquals(2, details.getThrowableStrRep().length);
            assertEquals("java.lang.Exception: boom",
                         details.getThrowableStrRep()[0]);
        } finally {
            socket.close();
        }
    }

    /**
     * Events sent by a SocketAppender configured with
     * input/xml/socketAppenderForChainsaw.xml must reach Chainsaw.
     */
    public void testReceivesEventsFromSocketAppender() throws Exception {
        startReceiver(CHAINSAW_CONFIG_PORT);
        DOMConfigurator.configure("input/xml/socketAppenderForChainsaw.xml");

        String message = "event sent by SocketAppender";
        Logger.getLogger(LoggingReceiverTest.class).info(message);

        EventDetails details = awaitEvent(message);
        assertNotNull("event from SocketAppender was not received", details);
        assertEquals(Level.INFO, details.getPriority());
        assertEquals(LoggingReceiverTest.class.getName(),
                     details.getCategoryName());
    }

    /* Helpers */

    /**
     * Starts a receiver feeding a new model.
     *
     * @param port port to listen on, 0 for any free port
     * @return the port the receiver listens on
     */
    private int startReceiver(final int port) throws Exception {
        model = new MyTableModel();
        receiver = new LoggingReceiver(model, port);
        receiver.start();
        return getServerSocket(receiver).getLocalPort();
    }

    private static ServerSocket getServerSocket(final LoggingReceiver r)
        throws Exception {
        Field field = LoggingReceiver.class.getDeclaredField("mSvrSock");
        field.setAccessible(true);
        return (ServerSocket) field.get(r);
    }

    /**
     * Sends a serialized object to the receiver and waits for the receiver
     * to close the connection.
     *
     * @return true if the receiver closed the connection
     */
    private static boolean sendAndAwaitClose(final int port,
                                             final Object payload)
        throws IOException {
        Socket socket = new Socket("localhost", port);
        try {
            socket.setSoTimeout(TIMEOUT);
            try {
                ObjectOutputStream oos =
                    new ObjectOutputStream(socket.getOutputStream());
                oos.writeObject(payload);
                oos.flush();
            } catch (SocketException e) {
                // the receiver closed the connection while the payload
                // was still being written
                return true;
            }

            // the receiver never writes back, so the only way out of this
            // read is the receiver closing the connection or the timeout
            InputStream in = socket.getInputStream();
            try {
                return in.read() == -1;
            } catch (SocketTimeoutException e) {
                return false;
            } catch (SocketException e) {
                // connection reset by the receiver
                return true;
            }
        } finally {
            socket.close();
        }
    }

    /**
     * Waits until the model displays an event with the given message.
     *
     * @return the event, or null if none arrived in time
     */
    private EventDetails awaitEvent(final String message)
        throws InterruptedException {
        long deadline = System.currentTimeMillis() + TIMEOUT;
        while (System.currentTimeMillis() < deadline) {
            EventDetails details = findEvent(message);
            if (details != null) {
                return details;
            }
            Thread.sleep(100);
        }
        return null;
    }

    private EventDetails findEvent(final String message) {
        int rows = model.getRowCount();
        for (int i = 0; i < rows; i++) {
            EventDetails details = model.getEventDetails(i);
            if (message.equals(details.getMessage())) {
                return details;
            }
        }
        return null;
    }

    /* Inner classes */

    /**
     * Stand-in for a deserialization gadget: records whether it was ever
     * instantiated through deserialization.
     */
    public static class Gadget implements Serializable {
        private static final long serialVersionUID = 1L;

        static volatile boolean deserialized = false;

        final String data;

        public Gadget(final String data) {
            this.data = data;
        }

        private void readObject(final ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            deserialized = true;
        }
    }
}
