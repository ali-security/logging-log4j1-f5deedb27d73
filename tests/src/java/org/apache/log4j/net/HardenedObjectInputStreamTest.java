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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /** Number of nesting levels of the attack payloads. */
    public static final int ATTACK_DEPTH = 100;

    /** Maximum time to wait for a payload to be read, in milliseconds. */
    private static final int TIMEOUT = 10000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Builds the CVE-2023-26464 attack payload from the logback advisory:
     * deeply nested HashSets that form a DAG causing O(2^depth) hashCode()
     * computation when the sets are rebuilt during deserialization.
     */
    public static Set createNestedHashSetPayload(final int depth) {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < depth; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Builds a DAG of maps of the given class in which every level holds
     * both maps of the next level as values, so that hashCode() of the root
     * visits O(2^depth) maps. The root is used as a key of the returned map,
     * which makes the deserializer hash it.
     */
    private static Map createNestedMapPayload(final Class mapClass,
                                              final int depth)
        throws Exception {
        Map outer = (Map) mapClass.newInstance();
        Map root = (Map) mapClass.newInstance();
        // root is still empty, so hashing it here is cheap
        outer.put(root, "root");
        Map m1 = root;
        Map m2 = (Map) mapClass.newInstance();
        for (int i = 0; i < depth; i++) {
            Map t1 = (Map) mapClass.newInstance();
            Map t2 = (Map) mapClass.newInstance();
            t1.put("foo", "bar");
            m1.put("left", t1);
            m1.put("right", t2);
            m2.put("left", t1);
            m2.put("right", t2);
            m1 = t1;
            m2 = t2;
        }
        return outer;
    }

    /**
     * Asserts that deserializing the payload is refused. The payload is
     * read in a separate thread so that an unmitigated payload fails the
     * test instead of hanging it.
     */
    private void assertRejected(final byte[] serialized) throws Exception {
        final Object[] outcome = new Object[1];
        Thread reader = new Thread() {
            public void run() {
                try {
                    ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
                    String[] whitelist = new String[0];
                    HardenedObjectInputStream hois =
                        new HardenedObjectInputStream(bis, whitelist);
                    try {
                        outcome[0] = hois.readObject();
                    } finally {
                        hois.close();
                    }
                } catch (Throwable t) {
                    outcome[0] = t;
                }
            }
        };
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT);

        assertFalse("Deserialization of the payload did not complete in time",
                    reader.isAlive());
        if (outcome[0] instanceof InvalidObjectException) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    ((Throwable) outcome[0]).getMessage().indexOf("collection") >= 0);
        } else if (!(outcome[0] instanceof java.io.InvalidClassException)) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
            fail("Payload should be rejected due to collection count limit, got "
                 + outcome[0]);
        }
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        assertRejected(serialize(createNestedHashSetPayload(ATTACK_DEPTH)));
    }

    /**
     * CVE-2023-26464: deeply nested HashMaps.
     */
    public void testDeeplyNestedHashMapRejected() throws Exception {
        assertRejected(serialize(
            createNestedMapPayload(HashMap.class, ATTACK_DEPTH)));
    }

    /**
     * CVE-2023-26464: deeply nested Hashtables.
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        assertRejected(serialize(
            createNestedMapPayload(Hashtable.class, ATTACK_DEPTH)));
    }

    /**
     * Map entries hash the objects they reference just like collections
     * do, so a DAG of nested entries hashed by a single HashSet must be
     * rejected as well.
     */
    public void testDeeplyNestedMapEntriesRejected() throws Exception {
        Object e1 = "foo";
        Object e2 = "bar";
        for (int i = 0; i < ATTACK_DEPTH; i++) {
            Object n1 = new AbstractMap.SimpleEntry(e1, e2);
            Object n2 = new AbstractMap.SimpleEntry(e2, e1);
            e1 = n1;
            e2 = n2;
        }
        Map.Entry holder = new AbstractMap.SimpleEntry("holder", null);
        Set root = new HashSet();
        // holder is hashed while it is still cheap to do so
        root.add(holder);
        holder.setValue(e1);

        assertRejected(serialize(root));
    }

    /**
     * A single object graph holding more collections than the limit is
     * rejected even when they are not nested.
     */
    public void testTooManyCollectionsRejected() throws Exception {
        assertRejected(serialize(
            createCollections(HardenedObjectInputStream.MAX_COLLECTION_COUNT + 1)));
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Each object read with readAdaptedObject() gets its own budget, so a
     * stream carrying many objects, each one right at the limit, is read
     * completely.
     */
    public void testEachReadAdaptedObjectHasItsOwnBudget() throws Exception {
        int objects = 3;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < objects; i++) {
            oos.writeObject(
                createCollections(HardenedObjectInputStream.MAX_COLLECTION_COUNT));
        }
        oos.close();

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);
        try {
            for (int i = 0; i < objects; i++) {
                Vector result = (Vector) hois.readAdaptedObject();
                assertEquals(HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1,
                             result.size());
            }
        } finally {
            hois.close();
        }
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * Creates an object graph holding exactly the given number of
     * collections: a vector of count - 1 empty vectors.
     */
    private static Vector createCollections(final int count) {
        Vector outer = new Vector();
        for (int i = 1; i < count; i++) {
            outer.addElement(new Vector());
        }
        return outer;
    }
}
