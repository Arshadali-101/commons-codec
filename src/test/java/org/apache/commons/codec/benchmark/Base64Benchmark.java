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

package org.apache.commons.codec.benchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
public class Base64Benchmark {

    private String input;

    @Setup
    public void setup() {
        input = "This is a test string for benchmarking Base64 encoding.";
    }

    @Benchmark
    public String testBase64Encode() {
        return org.apache.commons.codec.binary.Base64.encodeBase64String(input.getBytes());
    }

    @Benchmark
    public byte[] testBase64Decode() {
        return org.apache.commons.codec.binary.Base64.decodeBase64(input);
    }
}
