/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RegressionTest0 {

    public static boolean debug = false;

    @Test
    public void test01() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test01");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_256(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test02() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test02");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex("hi!");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "56bf5dbae43f77a63d075b0f2ae9c7c3e3098db93779c7f9840da0f4db9c2f8c8454f4edd1373e2b64ee2e68350d916e" + "'", str1, "56bf5dbae43f77a63d075b0f2ae9c7c3e3098db93779c7f9840da0f4db9c2f8c8454f4edd1373e2b64ee2e68350d916e");
    }

    @Test
    public void test03() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test03");
        byte[] byteArray6 = new byte[] { (byte) -1, (byte) 10, (byte) 10, (byte) 100, (byte) 1, (byte) 1 };
        java.lang.String str7 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(byteArray6);
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[-1, 10, 10, 100, 1, 1]");
        org.junit.Assert.assertEquals("'" + str7 + "' != '" + "a46f4a724e9005f9c4d9c71848410636d089325c2039433d6d8bdd63bf06b07a5bc4e13578506d2b996da7ec59727fb096108e9215f02f070cbf0b334adea98e" + "'", str7, "a46f4a724e9005f9c4d9c71848410636d089325c2039433d6d8bdd63bf06b07a5bc4e13578506d2b996da7ec59727fb096108e9215f02f070cbf0b334adea98e");
    }

    @Test
    public void test04() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test04");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils("4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException: 4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test05() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test05");
        java.security.MessageDigest messageDigest0 = null;
        java.io.InputStream inputStream1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test06() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test06");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test07() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test07");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot read the array length because \"input\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test08() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test08");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test09() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test09");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_256(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test10() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test10");
        byte[] byteArray2 = new byte[] { (byte) 10, (byte) 1 };
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(byteArray2);
        java.lang.Class<?> wildcardClass4 = byteArray2.getClass();
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[10, 1]");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b" + "'", str3, "4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b");
        org.junit.Assert.assertNotNull(wildcardClass4);
    }

    @Test
    public void test11() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test11");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test12() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test12");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test13() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test13");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_512(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test14() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test14");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_384Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-384 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test15() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test15");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("hi!");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "ef69960c8c35133f4d64adfe09f714f0b071374a5b277874309b869f" + "'", str1, "ef69960c8c35133f4d64adfe09f714f0b071374a5b277874309b869f");
    }

    @Test
    public void test16() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test16");
        // The following exception was thrown during execution in test generation
        try {
            org.apache.commons.codec.digest.DigestUtils digestUtils1 = new org.apache.commons.codec.digest.DigestUtils("");
            org.junit.Assert.fail("Expected exception of type java.lang.IllegalArgumentException; message: java.security.NoSuchAlgorithmException:  MessageDigest not available");
        } catch (java.lang.IllegalArgumentException e) {
            // Expected exception.
        }
    }

    @Test
    public void test17() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test17");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test18() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test18");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex("");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" + "'", str1, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    @Test
    public void test19() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test19");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        java.io.RandomAccessFile randomAccessFile1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, randomAccessFile1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.RandomAccessFile.getChannel()\" because \"data\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test20() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test20");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test21() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test21");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384("4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-71, -122, -33, -26, 82, -1, 108, 124, 15, 2, -107, 110, 108, 35, -103, 76, 108, 120, 62, 101, -95, 60, -113, -107, 93, -102, -45, 94, 123, -72, -67, -45, -94, -1, 50, 91, -4, -48, 10, 103, 71, -29, -7, 80, -70, -127, -122, -93]");
    }

    @Test
    public void test22() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test22");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex("4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "6e8bdf41c470e2111a76ba29b3bf06978f1a8c1e346952e22e73f85d" + "'", str1, "6e8bdf41c470e2111a76ba29b3bf06978f1a8c1e346952e22e73f85d");
    }

    @Test
    public void test23() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test23");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_512("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-76, 49, -32, -42, 18, 76, -36, -86, -72, 113, -53, 86, -43, 124, -21, -113, 114, -6, -68, -8, -11, -83, 118, 15, 18, 24, 127, -66, -111, -39, -94, -33, 30, 44, 71, -74, 24, -77, 72, 24, -100, -36, 51, 97, 93, 29, 62, 44, -1, 14, -49, 52, -89, 47, 15, 27, 35, -104, -24, 24, -1, -45, 75, 109]");
    }

    @Test
    public void test24() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test24");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha384("");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "4e3b533c39447aaeb59a8e48fabd7e15b5b5d195" + "'", str2, "4e3b533c39447aaeb59a8e48fabd7e15b5b5d195");
    }

    @Test
    public void test25() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test25");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test26() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test26");
        boolean boolean1 = org.apache.commons.codec.digest.DigestUtils.isAvailable("bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d");
        org.junit.Assert.assertTrue("'" + boolean1 + "' != '" + false + "'", boolean1 == false);
    }

    @Test
    public void test27() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test27");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha512_224Hex(byteArray2);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha384(byteArray2);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[75, 66, 82, 26, -127, -45, -100, 108, 63, 73, 82, 68, 92, 72, -99, 56, -44, 95, 89, -41, 39, 78, -70, 91, 12, -1, 57, 10]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-15, -37, 108, 19, 113, -51, 74, -87, 46, 10, -112, 112, -50, -16, -20, -54, -73, -127, -103, 119, 81, -95, 23, 45, 107, 114, -110, 52]");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "65063b6c3c13d93fd08f8e036ec4a0755e43dfad77c5a3fca865f10c" + "'", str3, "65063b6c3c13d93fd08f8e036ec4a0755e43dfad77c5a3fca865f10c");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[0, 69, -70, -69, 25, 97, 58, -82, -101, 45, 113, 105, 64, -41, -127, -124, 56, 47, -68, -118, -62, 74, 31, 83, 69, 94, 118, 1, -22, -15, 78, 90, 58, -17, -60, 19, 81, 50, -54, 113, 39, 8, -27, 16, -59, -34, 80, -64]");
    }

    @Test
    public void test28() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test28");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test29() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test29");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md2Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test30() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test30");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_256("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-114, -111, -8, -21, -115, -3, 62, 123, 71, 22, -34, 91, 36, -95, -107, -98, -10, 76, -126, 113, -96, -6, 11, 81, -102, -118, -64, -46, -50, 113, -99, 90]");
    }

    @Test
    public void test31() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test31");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224("6e8bdf41c470e2111a76ba29b3bf06978f1a8c1e346952e22e73f85d");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[30, -38, 57, 49, 70, -46, -84, 115, 0, -70, -17, -10, 118, 127, 63, -33, -123, -11, -124, 3, -40, 53, 59, -42, -87, 41, 122, 108]");
    }

    @Test
    public void test32() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test32");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha256("bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[87, 70, -17, 42, 60, 9, 106, -60, -63, -103, 93, -13, -107, 114, 18, -7, 103, -37, 15, -98, -15, -81, -27, -59, 50, -106, 92, -72, 106, 16, 27, -106]");
    }

    @Test
    public void test33() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test33");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray4);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray4);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(byteArray7);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <initialized>\r\n");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str5, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[117, -38, 106, -52, 90, -120, 109, 118, -12, 42, 124, -27, -5, 95, -30, 2, 111, 106, -102, -100, -23, 94, 112, 106, -19, 37, -20, -53, -25, 13, 99, 90]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[120, 103, 14, -120, -87, -62, -57, 17, 18, 68, 113, -46, -14, 74, -115, -68, -116, -27, -37, -87]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "c6e7cd40f662ea739584a8a67e96a0265f812d3f8dc0bd2905587f7bcc5f4a319bcfe391d65c6625fdc48175cee0e775" + "'", str8, "c6e7cd40f662ea739584a8a67e96a0265f812d3f8dc0bd2905587f7bcc5f4a319bcfe391d65c6625fdc48175cee0e775");
    }

    @Test
    public void test34() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test34");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test35() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test35");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha3_512Hex(byteArray1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[92, -34, -30, 97, -29, 82, 38, 89, 30, -107, 94, 51, -49, 42, -35, -51, 71, 4, 93, -113, -7, 106, -127, 81, -117, -54, 32, -84, 103, -15, 5, -107, 60, 99, -1, -43, -74, 37, -22, -14, -110, 73, -121, -26, 97, -12, -41, 44, 105, -29, 108, -56, -66, -38, 65, -11, -69, -23, -119, 119, 77, 84, 42, -75]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "7f2b772358e178e87ab7234156d8faa2d0fc0269ca7ed8fc76de1e1cac827e25912b1dd77af41884725509b51e084c46c0b9d4c6d9e25edfad8c7d15fd930221" + "'", str2, "7f2b772358e178e87ab7234156d8faa2d0fc0269ca7ed8fc76de1e1cac827e25912b1dd77af41884725509b51e084c46c0b9d4c6d9e25edfad8c7d15fd930221");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "96062739bf0d44fab3430e69581f396e82702a84bc0069f5e64cb4ad66d1342c" + "'", str3, "96062739bf0d44fab3430e69581f396e82702a84bc0069f5e64cb4ad66d1342c");
    }

    @Test
    public void test36() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test36");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        java.io.RandomAccessFile randomAccessFile1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, randomAccessFile1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.RandomAccessFile.getChannel()\" because \"data\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test37() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test37");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_256("");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-89, -1, -58, -8, -65, 30, -41, 102, 81, -63, 71, 86, -96, 97, -42, 98, -11, -128, -1, 77, -28, 59, 73, -6, -126, -40, 10, 75, -128, -8, 67, 74]");
    }

    @Test
    public void test38() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test38");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray1);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_384(byteArray1);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_384(byteArray3);
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray4);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[75, 66, 82, 26, -127, -45, -100, 108, 63, 73, 82, 68, 92, 72, -99, 56, -44, 95, 89, -41, 39, 78, -70, 91, 12, -1, 57, 10]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-15, -37, 108, 19, 113, -51, 74, -87, 46, 10, -112, 112, -50, -16, -20, -54, -73, -127, -103, 119, 81, -95, 23, 45, 107, 114, -110, 52]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-108, -46, -5, -23, -61, -91, 33, 16, 46, 85, 95, 75, 90, 100, 127, -106, -126, 27, 116, 102, 111, -64, 58, 21, -116, 37, -59, -122, -61, -8, 2, 32, 52, -17, -1, 91, -76, 116, 25, -66, -62, -109, 25, 36, 23, -13, -82, 110]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-66, 115, 24, 73, -69, -64, 12, 70, 83, -109, -127, -91, -40, 67, -114, -4, 61, 48, 102, -69, 19, 125, 90, 51, 53, 119, 39, -30, 22, -78, 1, 3, 103, 53, 33, -59, -84, 55, -100, 8, -70, -91, 91, -3, -20, -33, -57, -68]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "a835ad3d6370a89e8c4382ab9f99fad3c75d2feb5f4a5f4948405fa0d3925a2a" + "'", str5, "a835ad3d6370a89e8c4382ab9f99fad3c75d2feb5f4a5f4948405fa0d3925a2a");
    }

    @Test
    public void test39() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test39");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getShaDigest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-1 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test40() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test40");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_224(byteArray1);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha3_384(byteArray1);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_384(byteArray3);
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(byteArray3);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[75, 66, 82, 26, -127, -45, -100, 108, 63, 73, 82, 68, 92, 72, -99, 56, -44, 95, 89, -41, 39, 78, -70, 91, 12, -1, 57, 10]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-15, -37, 108, 19, 113, -51, 74, -87, 46, 10, -112, 112, -50, -16, -20, -54, -73, -127, -103, 119, 81, -95, 23, 45, 107, 114, -110, 52]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-108, -46, -5, -23, -61, -91, 33, 16, 46, 85, 95, 75, 90, 100, 127, -106, -126, 27, 116, 102, 111, -64, 58, 21, -116, 37, -59, -122, -61, -8, 2, 32, 52, -17, -1, 91, -76, 116, 25, -66, -62, -109, 25, 36, 23, -13, -82, 110]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-66, 115, 24, 73, -69, -64, 12, 70, 83, -109, -127, -91, -40, 67, -114, -4, 61, 48, 102, -69, 19, 125, 90, 51, 53, 119, 39, -30, 22, -78, 1, 3, 103, 53, 33, -59, -84, 55, -100, 8, -70, -91, 91, -3, -20, -33, -57, -68]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "5ab22c00d1afb0715dcd9e7a40bcfcfee74747560071603e8bfffea632cccc390199880922091b588a16cacef0d8b07f8d1b19ca538727a89068e80e89774eab" + "'", str5, "5ab22c00d1afb0715dcd9e7a40bcfcfee74747560071603e8bfffea632cccc390199880922091b588a16cacef0d8b07f8d1b19ca538727a89068e80e89774eab");
    }

    @Test
    public void test41() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test41");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_256Digest();
        java.nio.ByteBuffer byteBuffer1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteBuffer1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-256 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test42() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test42");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha384("");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha512_256(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[111, 92, 15, -7, -113, 93, 68, 97, 29, 69, -122, 18, 26, -120, 37, -84, 62, -26, 8, -14, 36, 66, 63, -92, 59, -8, 122, -16, 37, -84, -62, -105]");
    }

    @Test
    public void test43() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test43");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex("7f2b772358e178e87ab7234156d8faa2d0fc0269ca7ed8fc76de1e1cac827e25912b1dd77af41884725509b51e084c46c0b9d4c6d9e25edfad8c7d15fd930221");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "4e66d0b301a703609ab350e14de25bff74b733540b47c9dabf696cd89b0d593c" + "'", str1, "4e66d0b301a703609ab350e14de25bff74b733540b47c9dabf696cd89b0d593c");
    }

    @Test
    public void test44() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test44");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_384Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test45() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test45");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray4);
        java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, "bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d");
        java.nio.file.Path path9 = null;
        java.nio.file.OpenOption[] openOptionArray10 = new java.nio.file.OpenOption[] {};
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray11 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, path9, openOptionArray10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.nio.file.Path.getFileSystem()\" because \"path\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\r\n");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str5, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[117, -38, 106, -52, 90, -120, 109, 118, -12, 42, 124, -27, -5, 95, -30, 2, 111, 106, -102, -100, -23, 94, 112, 106, -19, 37, -20, -53, -25, 13, 99, 90]");
        org.junit.Assert.assertNotNull(messageDigest8);
        org.junit.Assert.assertEquals(messageDigest8.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\r\n");
        org.junit.Assert.assertNotNull(openOptionArray10);
    }

    @Test
    public void test46() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test46");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.shaHex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test47() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test47");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getMd5Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "MD5 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test48() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test48");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md2("65063b6c3c13d93fd08f8e036ec4a0755e43dfad77c5a3fca865f10c");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-90, 63, 36, -55, -56, -48, -80, 17, -19, -56, 58, -100, 25, -48, -114, 78]");
    }

    @Test
    public void test49() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test49");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.shaHex("5ab22c00d1afb0715dcd9e7a40bcfcfee74747560071603e8bfffea632cccc390199880922091b588a16cacef0d8b07f8d1b19ca538727a89068e80e89774eab");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "65e9f787270d874dda710a795525628e7132133d" + "'", str1, "65e9f787270d874dda710a795525628e7132133d");
    }

    @Test
    public void test50() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test50");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_256Digest();
        java.io.InputStream inputStream1 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest2 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, inputStream1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-256 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test51() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test51");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384("56bf5dbae43f77a63d075b0f2ae9c7c3e3098db93779c7f9840da0f4db9c2f8c8454f4edd1373e2b64ee2e68350d916e");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray1);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.sha(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[92, -11, 18, 116, -117, 39, 93, -61, -107, 94, -73, 20, 43, -97, 18, -105, -16, -94, -33, -122, 47, 49, -1, -40, 45, -86, 40, -76, 8, -41, -109, -39, -117, 109, -32, 38, 112, -117, -104, -103, -39, -51, 8, 68, -84, -89, 125, 27]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-19, -57, -32, 40, 99, -90, -79, 27, 48, -75, 22, -1, 88, -100, 110, 106, -108, 4, -31, 61, -42, -89, 88, 96, -70, -37, -9, -80]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-95, 122, -126, -114, 80, 54, 122, -6, -7, -23, 13, 71, -78, -94, -19, 17, 16, -82, -125, -82]");
    }

    @Test
    public void test52() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test52");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray4);
        byte[] byteArray7 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray4);
        java.lang.String str8 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray4);
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <initialized>\r\n");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str5, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[117, -38, 106, -52, 90, -120, 109, 118, -12, 42, 124, -27, -5, 95, -30, 2, 111, 106, -102, -100, -23, 94, 112, 106, -19, 37, -20, -53, -25, 13, 99, 90]");
        org.junit.Assert.assertNotNull(byteArray7);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray7), "[120, 103, 14, -120, -87, -62, -57, 17, 18, 68, 113, -46, -14, 74, -115, -68, -116, -27, -37, -87]");
        org.junit.Assert.assertEquals("'" + str8 + "' != '" + "5ae7e6a42304dc6e4176210b83c43024f99a0bce9a870c3b6d2c95fc8ebfb74c" + "'", str8, "5ae7e6a42304dc6e4176210b83c43024f99a0bce9a870c3b6d2c95fc8ebfb74c");
    }

    @Test
    public void test53() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test53");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha1Digest();
        java.nio.file.Path path1 = null;
        java.nio.file.OpenOption[] openOptionArray2 = new java.nio.file.OpenOption[] {};
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, path1, openOptionArray2);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.nio.file.Path.getFileSystem()\" because \"path\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-1 Message Digest from SUN, <initialized>\r\n");
        org.junit.Assert.assertNotNull(openOptionArray2);
    }

    @Test
    public void test54() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test54");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_224Digest();
        java.io.RandomAccessFile randomAccessFile1 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, randomAccessFile1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.RandomAccessFile.getChannel()\" because \"data\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-224 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test55() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test55");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot read the array length because \"input\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test56() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test56");
        byte[] byteArray0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot read the array length because \"input\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test57() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test57");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha512_256Digest();
        byte[] byteArray4 = new byte[] { (byte) -1, (byte) -1, (byte) -1 };
        java.lang.String str5 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray4);
        byte[] byteArray6 = org.apache.commons.codec.digest.DigestUtils.digest(messageDigest0, byteArray4);
        java.security.MessageDigest messageDigest8 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, "bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d");
        java.nio.file.Path path9 = null;
        java.nio.file.OpenOption[] openOptionArray10 = new java.nio.file.OpenOption[] {};
        // The following exception was thrown during execution in test generation
        try {
            java.security.MessageDigest messageDigest11 = org.apache.commons.codec.digest.DigestUtils.updateDigest(messageDigest0, path9, openOptionArray10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.nio.file.Path.getFileSystem()\" because \"path\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\r\n");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-1, -1, -1]");
        org.junit.Assert.assertEquals("'" + str5 + "' != '" + "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a" + "'", str5, "75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        org.junit.Assert.assertNotNull(byteArray6);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray6), "[117, -38, 106, -52, 90, -120, 109, 118, -12, 42, 124, -27, -5, 95, -30, 2, 111, 106, -102, -100, -23, 94, 112, 106, -19, 37, -20, -53, -25, 13, 99, 90]");
        org.junit.Assert.assertNotNull(messageDigest8);
        org.junit.Assert.assertEquals(messageDigest8.toString(), "SHA-512/256 Message Digest from SUN, <in progress>\r\n");
        org.junit.Assert.assertNotNull(openOptionArray10);
    }

    @Test
    public void test58() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test58");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_256("4e66d0b301a703609ab350e14de25bff74b733540b47c9dabf696cd89b0d593c");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-54, -90, -15, 58, 33, -24, -53, -123, 17, -96, 126, 81, 7, 91, 28, 19, -93, -56, 27, -53, -15, -3, 100, 53, 126, -78, 39, 50, 30, -107, -115, -78]");
    }

    @Test
    public void test59() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test59");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha384("");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex(byteArray1);
        java.lang.String str3 = org.apache.commons.codec.digest.DigestUtils.sha3_224Hex(byteArray1);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha1(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[56, -80, 96, -89, 81, -84, -106, 56, 76, -39, 50, 126, -79, -79, -29, 106, 33, -3, -73, 17, 20, -66, 7, 67, 76, 12, -57, -65, 99, -10, -31, -38, 39, 78, -34, -65, -25, 111, 101, -5, -43, 26, -46, -15, 72, -104, -71, 91]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297" + "'", str2, "6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297");
        org.junit.Assert.assertEquals("'" + str3 + "' != '" + "bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d" + "'", str3, "bb02756bbc6642979780e799d6f4c1bd3a35a38ba241aceac842e05d");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[78, 59, 83, 60, 57, 68, 122, -82, -75, -102, -114, 72, -6, -67, 126, 21, -75, -75, -47, -107]");
    }

    @Test
    public void test60() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test60");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex("a46f4a724e9005f9c4d9c71848410636d089325c2039433d6d8bdd63bf06b07a5bc4e13578506d2b996da7ec59727fb096108e9215f02f070cbf0b334adea98e");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "121782ca8f0c7684283c4a10b29c4a8ee01ba9c9c0aee8f72c664b5fed578e35" + "'", str1, "121782ca8f0c7684283c4a10b29c4a8ee01ba9c9c0aee8f72c664b5fed578e35");
    }

    @Test
    public void test61() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test61");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512_224("a46f4a724e9005f9c4d9c71848410636d089325c2039433d6d8bdd63bf06b07a5bc4e13578506d2b996da7ec59727fb096108e9215f02f070cbf0b334adea98e");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.md5(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-106, -22, -41, -41, 111, -88, -110, 126, -1, -24, 99, -45, -120, -2, -68, -18, 8, 82, -30, -99, 82, 18, 25, 102, 46, 36, -4, -5]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[123, -54, -43, 113, -6, 24, -17, -127, -59, 33, -81, 9, -22, 79, -79, -57]");
    }

    @Test
    public void test62() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test62");
        java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha512_256Hex("6f5c0ff98f5d44611d4586121a8825ac3ee608f224423fa43bf87af025acc297");
        org.junit.Assert.assertEquals("'" + str1 + "' != '" + "7840baee4fb45da6fd41f292d2b4e8733a5b780d1d85dd5655732dd3089260a6" + "'", str1, "7840baee4fb45da6fd41f292d2b4e8733a5b780d1d85dd5655732dd3089260a6");
    }

    @Test
    public void test63() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test63");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_224("a46f4a724e9005f9c4d9c71848410636d089325c2039433d6d8bdd63bf06b07a5bc4e13578506d2b996da7ec59727fb096108e9215f02f070cbf0b334adea98e");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[18, -13, 75, 52, 117, 9, -126, -80, 113, 84, 16, 12, 26, 68, 45, 20, 52, -46, 29, 7, -62, 58, 61, 108, 22, 66, 96, -46]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-39, -119, -119, 22, -54, 25, -33, -71, -31, 126, -19, 99, -91, -124, -45, -40, 3, 44, -98, 99]");
    }

    @Test
    public void test64() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test64");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md2(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test65() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test65");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.md5("4e1b00dc86a4e1998bcf75dd69a3912a84474bc1e5b547be80595e07ea84de52ee3b63668720b819948d74bb1e8334a8aa7128772b10d39f3f67f8ad3a07998b");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[48, -8, -53, -102, -36, 77, 1, -32, -45, 106, 8, 118, 116, 3, -109, 80]");
    }

    @Test
    public void test66() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test66");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.md5Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test67() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test67");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha512("75da6acc5a886d76f42a7ce5fb5fe2026f6a9a9ce95e706aed25eccbe70d635a");
        java.lang.String str2 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[92, -34, -30, 97, -29, 82, 38, 89, 30, -107, 94, 51, -49, 42, -35, -51, 71, 4, 93, -113, -7, 106, -127, 81, -117, -54, 32, -84, 103, -15, 5, -107, 60, 99, -1, -43, -74, 37, -22, -14, -110, 73, -121, -26, 97, -12, -41, 44, 105, -29, 108, -56, -66, -38, 65, -11, -69, -23, -119, 119, 77, 84, 42, -75]");
        org.junit.Assert.assertEquals("'" + str2 + "' != '" + "e7e1756ba0eb967204ee5a82bb3e20e8bfa857f0c73397d9d7cfca84d1b7f3be" + "'", str2, "e7e1756ba0eb967204ee5a82bb3e20e8bfa857f0c73397d9d7cfca84d1b7f3be");
    }

    @Test
    public void test68() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test68");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_512("c6e7cd40f662ea739584a8a67e96a0265f812d3f8dc0bd2905587f7bcc5f4a319bcfe391d65c6625fdc48175cee0e775");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-1, -85, -97, -82, 43, 26, 106, -17, 107, -30, -82, -103, -21, 87, -23, -87, -43, 79, -103, -63, 106, -107, -83, -78, -2, 28, -27, -21, 64, -21, -52, 19, -125, -89, 57, -100, 95, -49, 17, 51, -36, -19, -79, -56, -76, -82, 40, 13, 67, -80, 55, -4, -50, 111, -1, 79, -49, -19, 23, -16, 116, 124, -113, -57]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-18, 47, 8, -66, -111, -102, 112, 113, -110, -115, -54, -127, -113, 32, -50, 124, -70, 42, 41, 35]");
    }

    @Test
    public void test69() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test69");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha3_256Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test70() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test70");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_256("96062739bf0d44fab3430e69581f396e82702a84bc0069f5e64cb4ad66d1342c");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[-93, -49, -108, 117, 124, -83, 126, 116, -9, 26, -14, -37, -124, -54, -70, -30, 64, 3, -61, -62, -20, 104, -42, 72, 26, 81, 115, -64, -101, 6, 63, 29]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-6, -121, -110, -77, 98, -37, -52, 66, 45, 106, -59, 69, -77, 101, -59, -44, 109, 14, 87, 73, -107, 64, -64, -53, -17, -76, -19, 44]");
    }

    @Test
    public void test71() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test71");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha("4e66d0b301a703609ab350e14de25bff74b733540b47c9dabf696cd89b0d593c");
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[53, 84, 17, -105, -43, 1, -110, 3, -76, -20, -66, -97, -85, -64, -72, -96, 63, 29, 54, -90]");
    }

    @Test
    public void test72() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test72");
        java.security.MessageDigest messageDigest0 = org.apache.commons.codec.digest.DigestUtils.getSha3_512Digest();
        org.junit.Assert.assertNotNull(messageDigest0);
        org.junit.Assert.assertEquals(messageDigest0.toString(), "SHA3-512 Message Digest from SUN, <initialized>\r\n");
    }

    @Test
    public void test73() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test73");
        java.io.InputStream inputStream0 = null;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.String str1 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(inputStream0);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"java.io.InputStream.read(byte[], int, int)\" because \"inputStream\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test74() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "RegressionTest0.test74");
        byte[] byteArray1 = org.apache.commons.codec.digest.DigestUtils.sha3_384("56bf5dbae43f77a63d075b0f2ae9c7c3e3098db93779c7f9840da0f4db9c2f8c8454f4edd1373e2b64ee2e68350d916e");
        byte[] byteArray2 = org.apache.commons.codec.digest.DigestUtils.sha3_224(byteArray1);
        byte[] byteArray3 = org.apache.commons.codec.digest.DigestUtils.md5(byteArray1);
        byte[] byteArray4 = org.apache.commons.codec.digest.DigestUtils.sha3_384(byteArray1);
        org.junit.Assert.assertNotNull(byteArray1);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray1), "[92, -11, 18, 116, -117, 39, 93, -61, -107, 94, -73, 20, 43, -97, 18, -105, -16, -94, -33, -122, 47, 49, -1, -40, 45, -86, 40, -76, 8, -41, -109, -39, -117, 109, -32, 38, 112, -117, -104, -103, -39, -51, 8, 68, -84, -89, 125, 27]");
        org.junit.Assert.assertNotNull(byteArray2);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray2), "[-19, -57, -32, 40, 99, -90, -79, 27, 48, -75, 22, -1, 88, -100, 110, 106, -108, 4, -31, 61, -42, -89, 88, 96, -70, -37, -9, -80]");
        org.junit.Assert.assertNotNull(byteArray3);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray3), "[-42, 39, 39, 35, -117, 94, -39, -101, 86, 104, -110, -96, -37, -73, -47, -4]");
        org.junit.Assert.assertNotNull(byteArray4);
        org.junit.Assert.assertEquals(java.util.Arrays.toString(byteArray4), "[-59, 85, 124, 118, -72, 49, -15, 119, 29, 107, -38, -80, 103, 84, 28, -97, -39, 50, 86, 86, 61, 102, -125, -127, -62, 97, 97, -124, -17, 105, 93, -121, -54, 6, 98, -106, -84, -119, -112, -118, -64, -101, 17, -45, -122, -76, 95, -117]");
    }
}

