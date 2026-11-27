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
package org.apache.log4j.nt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.StringTokenizer;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Library preloading tests for {@link NTEventLogAppender} (sonatype-2010-0053).
 *
 * The appender loaded its native library with System.loadLibrary only, so
 * the first library of that name found on the search path was loaded: a
 * library planted in one of those directories (the current directory or a
 * PATH entry on Windows) ran inside the JVM. When the
 * log4j.nteventlog.dll.path system property names the library by absolute
 * path, that file must be loaded and nothing from the search path.
 *
 * The NTEventLogAppenderDllPreloading target of tests/build.xml runs these
 * tests on Linux, with java.library.path set to {@link #PLANTED_DIR} in
 * place of the Windows search path. A copy of a JDK native library stands in
 * for the appender's library, and /proc/self/maps tells which copy the
 * operating system actually loaded.
 */
public class NTEventLogAppenderDllPreloadingTest extends TestCase {

    /** Directory on java.library.path where the attacker plants libraries. */
    private static final String PLANTED_DIR = "output/nteventlog/planted";

    /** Directory, off the search path, holding the library the user trusts. */
    private static final String TRUSTED_DIR = "output/nteventlog/trusted";

    /** JDK libraries without native methods of their own, used as stand-ins. */
    private static final String[] STAND_IN_LIBRARIES = { "verify", "zip" };

    private static File trustedLibrary;
    private static File[] plantedLibraries;
    private static Throwable initializationFailure;
    private static boolean initialized = false;

    /**
     *  Create new instance.
     */
    public NTEventLogAppenderDllPreloadingTest(final String testName) {
        super(testName);
    }

    /**
     * Runs these tests and, once the appender class is initialized, the
     * resolver tests of NTEventLogAppenderTest.
     */
    public static Test suite() {
        TestSuite suite = new TestSuite();
        suite.addTestSuite(NTEventLogAppenderDllPreloadingTest.class);
        suite.addTestSuite(NTEventLogAppenderTest.class);
        return new TestSetup(suite) {
            protected void setUp() throws Exception {
                initializeAppenderClass();
            }
        };
    }

    protected void setUp() throws Exception {
        initializeAppenderClass();
    }

    /**
     * Initializes the appender class once, recording any failure for the
     * tests to report.
     */
    private static synchronized void initializeAppenderClass() {
        if (initialized) {
            return;
        }
        initialized = true;
        try {
            loadAppenderClass();
        } catch (Throwable t) {
            initializationFailure = t;
        }
    }

    /**
     * Plants a library under each name the appender looks up on the search
     * path, points log4j.nteventlog.dll.path at the trusted library and
     * initializes the appender class, which loads its native library.
     */
    private static void loadAppenderClass() throws Exception {
        File plantedDir = new File(PLANTED_DIR).getCanonicalFile();
        assertTrue("java.library.path must include " + plantedDir
                + ", run these tests with the NTEventLogAppenderDllPreloading target"
                + " of tests/build.xml",
                isOnLibraryPath(plantedDir));
        File trustedDir = new File(TRUSTED_DIR).getCanonicalFile();
        plantedDir.mkdirs();
        trustedDir.mkdirs();

        File standIn = findStandInLibrary();
        trustedLibrary = new File(trustedDir, System.mapLibraryName("NTEventLogAppender"));
        copy(standIn, trustedLibrary);
        plantedLibraries = new File[] {
            new File(plantedDir, System.mapLibraryName(
                    "NTEventLogAppender." + System.getProperty("os.arch"))),
            new File(plantedDir, System.mapLibraryName("NTEventLogAppender"))
        };
        for (int i = 0; i < plantedLibraries.length; i++) {
            copy(standIn, plantedLibraries[i]);
        }

        String originalDllPath = System.getProperty("log4j.nteventlog.dll.path");
        System.setProperty("log4j.nteventlog.dll.path", trustedLibrary.getAbsolutePath());
        try {
            Class.forName("org.apache.log4j.nt.NTEventLogAppender");
        } finally {
            if (originalDllPath != null) {
                System.setProperty("log4j.nteventlog.dll.path", originalDllPath);
            } else {
                System.getProperties().remove("log4j.nteventlog.dll.path");
            }
        }
    }

    /**
     * A library planted on the search path must not be loaded when
     * log4j.nteventlog.dll.path names the library by absolute path.
     */
    public void testPlantedLibraryIsNotLoaded() throws IOException {
        assertInitialized();
        for (int i = 0; i < plantedLibraries.length; i++) {
            assertFalse("library planted on the search path was loaded: "
                    + plantedLibraries[i],
                    isLoaded(plantedLibraries[i]));
        }
    }

    /**
     * The library named by log4j.nteventlog.dll.path is the one loaded.
     */
    public void testConfiguredLibraryIsLoaded() throws IOException {
        assertInitialized();
        assertTrue("library named by log4j.nteventlog.dll.path was not loaded: "
                + trustedLibrary,
                isLoaded(trustedLibrary));
    }

    private static void assertInitialized() {
        if (initializationFailure != null) {
            fail("NTEventLogAppender could not be initialized: " + initializationFailure);
        }
    }

    private static boolean isOnLibraryPath(final File dir) throws IOException {
        String libraryPath = System.getProperty("java.library.path");
        if (libraryPath == null) {
            return false;
        }
        StringTokenizer tokens = new StringTokenizer(libraryPath, File.pathSeparator);
        while (tokens.hasMoreTokens()) {
            if (new File(tokens.nextToken()).getCanonicalFile().equals(dir)) {
                return true;
            }
        }
        return false;
    }

    private static File findStandInLibrary() {
        String bootPath = System.getProperty("sun.boot.library.path", "");
        for (int i = 0; i < STAND_IN_LIBRARIES.length; i++) {
            StringTokenizer tokens = new StringTokenizer(bootPath, File.pathSeparator);
            while (tokens.hasMoreTokens()) {
                File candidate = new File(tokens.nextToken(),
                        System.mapLibraryName(STAND_IN_LIBRARIES[i]));
                if (candidate.isFile()) {
                    return candidate;
                }
            }
        }
        fail("no JDK native library to stand in for NTEventLogAppender in " + bootPath);
        return null;
    }

    private static void copy(final File from, final File to) throws IOException {
        InputStream in = new FileInputStream(from);
        try {
            OutputStream out = new FileOutputStream(to);
            try {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    out.write(buffer, 0, count);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    /**
     * Whether the operating system mapped the library into this process.
     */
    private static boolean isLoaded(final File library) throws IOException {
        File maps = new File("/proc/self/maps");
        assertTrue("/proc/self/maps is required to tell which library was loaded",
                maps.exists());
        String path = library.getCanonicalPath();
        BufferedReader reader = new BufferedReader(new FileReader(maps));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.endsWith(" " + path)) {
                    return true;
                }
            }
        } finally {
            reader.close();
        }
        return false;
    }
}
