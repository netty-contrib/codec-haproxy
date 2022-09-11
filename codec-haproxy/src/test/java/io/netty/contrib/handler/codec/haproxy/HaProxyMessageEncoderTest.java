/*
 * Copyright 2021 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.contrib.handler.codec.haproxy;

import io.netty5.buffer.Buffer;
import io.netty5.buffer.internal.InternalBufferUtils;
import io.netty5.channel.embedded.EmbeddedChannel;
import io.netty.contrib.handler.codec.haproxy.HAProxyTLV.Type;
import io.netty5.util.ByteProcessor;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static io.netty.contrib.handler.codec.haproxy.HAProxyConstants.*;
import static io.netty.contrib.handler.codec.haproxy.HAProxyMessageEncoder.*;
import static io.netty5.buffer.BufferUtil.writeAscii;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HaProxyMessageEncoderTest {

    private static final int V2_HEADER_BYTES_LENGTH = 16;
    private static final int IPv4_ADDRESS_BYTES_LENGTH = 12;
    private static final int IPv6_ADDRESS_BYTES_LENGTH = 36;

    @Test
    public void testIPV4EncodeProxyV1() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V1, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                "192.168.0.1", "192.168.0.11", 56324, 443);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {
            assertEquals("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n",
                    buffer.toString(StandardCharsets.US_ASCII));
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testIPV6EncodeProxyV1() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V1, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP6,
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "1050:0:0:0:5:600:300c:326b", 56324, 443);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {
            assertEquals("PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 1050:0:0:0:5:600:300c:326b 56324 443\r\n",
                    buffer.toString(StandardCharsets.US_ASCII));
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testIPv4EncodeProxyV2() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                "192.168.0.1", "192.168.0.11", 56324, 443);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {
            // header
            byte[] headerBytes = new byte[12];
            buffer.readBytes(headerBytes, 0, headerBytes.length);
            assertArrayEquals(BINARY_PREFIX, headerBytes);

            // command
            byte commandByte = buffer.readByte();
            assertEquals(0x02, (commandByte & 0xf0) >> 4);
            assertEquals(0x01, commandByte & 0x0f);

            // transport protocol, address family
            byte transportByte = buffer.readByte();
            assertEquals(0x01, (transportByte & 0xf0) >> 4);
            assertEquals(0x01, transportByte & 0x0f);

            // source address length
            int sourceAddrLength = buffer.readUnsignedShort();
            assertEquals(12, sourceAddrLength);

            // source address
            byte[] sourceAddr = new byte[4];
            buffer.readBytes(sourceAddr, 0, sourceAddr.length);
            assertArrayEquals(new byte[]{(byte) 0xc0, (byte) 0xa8, 0x00, 0x01}, sourceAddr);

            // destination address
            byte[] destAddr = new byte[4];
            buffer.readBytes(destAddr, 0, destAddr.length);
            assertArrayEquals(new byte[]{(byte) 0xc0, (byte) 0xa8, 0x00, 0x0b}, destAddr);

            // source port
            int sourcePort = buffer.getUnsignedShort(24);
            assertEquals(56324, sourcePort);

            // destination port
            int destPort = buffer.getUnsignedShort(26);
            assertEquals(443, destPort);
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testIPv6EncodeProxyV2() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP6,
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "1050:0:0:0:5:600:300c:326b", 56324, 443);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {
            // header
            byte[] headerBytes = new byte[12];
            buffer.readBytes(headerBytes, 0, headerBytes.length);
            assertArrayEquals(BINARY_PREFIX, headerBytes);

            // command
            byte commandByte = buffer.readByte();
            assertEquals(0x02, (commandByte & 0xf0) >> 4);
            assertEquals(0x01, commandByte & 0x0f);

            // transport protocol, address family
            byte transportByte = buffer.readByte();
            assertEquals(0x02, (transportByte & 0xf0) >> 4);
            assertEquals(0x01, transportByte & 0x0f);

            // source address length
            int sourceAddrLength = buffer.readUnsignedShort();
            assertEquals(IPv6_ADDRESS_BYTES_LENGTH, sourceAddrLength);

            // source address
            byte[] sourceAddr = new byte[16];
            buffer.readBytes(sourceAddr, 0, sourceAddr.length);
            assertArrayEquals(new byte[]{
                    (byte) 0x20, (byte) 0x01, 0x0d, (byte) 0xb8,
                    (byte) 0x85, (byte) 0xa3, 0x00, 0x00, 0x00, 0x00, (byte) 0x8a, 0x2e,
                    0x03, 0x70, 0x73, 0x34
            }, sourceAddr);

            // destination address
            byte[] destAddr = new byte[16];
            buffer.readBytes(destAddr, 0, destAddr.length);
            assertArrayEquals(new byte[]{
                    (byte) 0x10, (byte) 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x05, 0x06, 0x00, 0x30, 0x0c, 0x32, 0x6b
            }, destAddr);

            // source port
            int sourcePort = buffer.getUnsignedShort(48);
            assertEquals(56324, sourcePort);

            // destination port
            int destPort = buffer.getUnsignedShort(50);
            assertEquals(443, destPort);
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testUnixEncodeProxyV2() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.UNIX_STREAM,
                "/var/run/src.sock", "/var/run/dst.sock", 0, 0);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {
            // header
            byte[] headerBytes = new byte[12];
            buffer.readBytes(headerBytes, 0, headerBytes.length);
            assertArrayEquals(BINARY_PREFIX, headerBytes);

            // command
            byte commandByte = buffer.getByte(12);
            assertEquals(0x02, (commandByte & 0xf0) >> 4);
            assertEquals(0x01, commandByte & 0x0f);

            // transport protocol, address family
            byte transportByte = buffer.getByte(13);
            assertEquals(0x03, (transportByte & 0xf0) >> 4);
            assertEquals(0x01, transportByte & 0x0f);

            // address length
            int addrLength = buffer.getUnsignedShort(14);
            assertEquals(TOTAL_UNIX_ADDRESS_BYTES_LENGTH, addrLength);

            // source address
            int bytes = buffer.openCursor(16, 108).process(ByteProcessor.FIND_NUL);
            assertEquals("/var/run/src.sock", InternalBufferUtils.copyToCharSequence(buffer, 16, bytes, StandardCharsets.US_ASCII));

            // destination address
            bytes = buffer.openCursor(124, 108).process(ByteProcessor.FIND_NUL);
            assertEquals("/var/run/dst.sock", InternalBufferUtils.copyToCharSequence(buffer, 124, bytes, StandardCharsets.US_ASCII));
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testTLVEncodeProxy() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        List<HAProxyTLV> tlvs = new ArrayList<>();

        try (Buffer helloWorld = writeAscii(ch.bufferAllocator(), "hello world");
             Buffer arbitrary = writeAscii(ch.bufferAllocator(), "an arbitrary string")) {
            HAProxyTLV alpnTlv = new HAProxyTLV(Type.PP2_TYPE_ALPN, (byte) 0x01, helloWorld.copy());
            tlvs.add(alpnTlv);

            HAProxyTLV authorityTlv = new HAProxyTLV(Type.PP2_TYPE_AUTHORITY, (byte) 0x01, arbitrary.copy());
            tlvs.add(authorityTlv);

            HAProxyMessage message = new HAProxyMessage(
                    HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                    "192.168.0.1", "192.168.0.11", 56324, 443, tlvs);
            assertTrue(ch.writeOutbound(message));

            try (Buffer buffer = ch.readOutbound()) {
                // length
                assertEquals(buffer.getUnsignedShort(14), buffer.readableBytes() - V2_HEADER_BYTES_LENGTH);

                // skip to tlv section
                buffer.skipReadableBytes(V2_HEADER_BYTES_LENGTH + IPv4_ADDRESS_BYTES_LENGTH);

                // alpn tlv
                assertEquals(alpnTlv.typeByteValue(), buffer.readByte());
                short bufLength = buffer.readShort();
                assertEquals(helloWorld.readableBytes(), bufLength);
                try (Buffer copy = buffer.copy(buffer.readerOffset(), bufLength)) {
                    assertEquals(helloWorld, copy);
                }

                buffer.skipReadableBytes(bufLength);

                // authority tlv
                assertEquals(authorityTlv.typeByteValue(), buffer.readByte());
                bufLength = buffer.readShort();
                assertEquals(arbitrary.readableBytes(), bufLength);
                try (Buffer copy = buffer.copy(buffer.readerOffset(), bufLength)) {
                    assertEquals(arbitrary, copy);
                }
            }
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testSslTLVEncodeProxy() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        List<HAProxyTLV> tlvs = new ArrayList<>();

        try (Buffer helloWorld = writeAscii(ch.bufferAllocator(), "hello world");
             Buffer arbitrary = writeAscii(ch.bufferAllocator(), "an arbitrary string")) {
            HAProxyTLV alpnTlv = new HAProxyTLV(Type.PP2_TYPE_ALPN, (byte) 0x01, helloWorld.copy());
            tlvs.add(alpnTlv);

            HAProxyTLV authorityTlv = new HAProxyTLV(Type.PP2_TYPE_AUTHORITY, (byte) 0x01, arbitrary.copy());
            tlvs.add(authorityTlv);

            HAProxySSLTLV haProxySSLTLV = new HAProxySSLTLV(1, (byte) 0x01, tlvs,
                    writeAscii(ch.bufferAllocator(), "some ssl content"));

            HAProxyMessage message = new HAProxyMessage(
                    HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                    "192.168.0.1", "192.168.0.11", 56324, 443,
                    Collections.<HAProxyTLV>singletonList(haProxySSLTLV));
            assertTrue(ch.writeOutbound(message));

            try (Buffer buffer = ch.readOutbound()) {
                assertEquals(buffer.getUnsignedShort(14), buffer.readableBytes() - V2_HEADER_BYTES_LENGTH);
                buffer.skipReadableBytes(V2_HEADER_BYTES_LENGTH + IPv4_ADDRESS_BYTES_LENGTH);

                // ssl tlv type
                assertEquals(haProxySSLTLV.typeByteValue(), buffer.readByte());

                // length
                int bufLength = buffer.readUnsignedShort();
                assertEquals(bufLength, buffer.readableBytes());

                // client, verify
                assertEquals(0x01, buffer.readByte());
                assertEquals(1, buffer.readInt());

                // alpn tlv
                assertEquals(alpnTlv.typeByteValue(), buffer.readByte());
                bufLength = buffer.readShort();
                assertEquals(helloWorld.readableBytes(), bufLength);
                try (Buffer copy = buffer.copy(buffer.readerOffset(), bufLength)) {
                    assertEquals(helloWorld, copy);
                }

                buffer.skipReadableBytes(bufLength);

                // authority tlv
                assertEquals(authorityTlv.typeByteValue(), buffer.readByte());
                bufLength = buffer.readShort();
                assertEquals(arbitrary.readableBytes(), bufLength);
                try (Buffer copy = buffer.copy(buffer.readerOffset(), bufLength)) {
                    assertEquals(arbitrary, copy);
                }
            }
        }
        assertFalse(ch.finish());
    }

    @Test
    public void testEncodeLocalProxyV2() {
        EmbeddedChannel ch = new EmbeddedChannel(INSTANCE);

        HAProxyMessage message = new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.LOCAL, HAProxyProxiedProtocol.UNKNOWN,
                null, null, 0, 0);
        assertTrue(ch.writeOutbound(message));

        try (Buffer buffer = ch.readOutbound()) {

            // header
            byte[] headerBytes = new byte[12];
            buffer.readBytes(headerBytes, 0, headerBytes.length);
            assertArrayEquals(BINARY_PREFIX, headerBytes);

            // command
            byte commandByte = buffer.readByte();
            assertEquals(0x02, (commandByte & 0xf0) >> 4);
            assertEquals(0x00, commandByte & 0x0f);

            // transport protocol, address family
            byte transportByte = buffer.readByte();
            assertEquals(0x00, transportByte);

            // source address length
            int sourceAddrLength = buffer.readUnsignedShort();
            assertEquals(0, sourceAddrLength);

            assertEquals(0, buffer.readableBytes());

        }
        assertFalse(ch.finish());
    }

    @Test
    public void testInvalidIpV4Address() {
        String invalidIpv4Address = "192.168.0.1234";
        assertThrows(IllegalArgumentException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V1, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                invalidIpv4Address, "192.168.0.11", 56324, 443));
    }

    @Test
    public void testInvalidIpV6Address() {
        String invalidIpv6Address = "2001:0db8:85a3:0000:0000:8a2e:0370:73345";
        assertThrows(IllegalArgumentException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V1, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP6,
                invalidIpv6Address, "1050:0:0:0:5:600:300c:326b", 56324, 443));
    }

    @Test
    public void testInvalidUnixAddress() {
        String invalidUnixAddress = new String(new byte[UNIX_ADDRESS_BYTES_LENGTH + 1]);
        assertThrows(IllegalArgumentException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.UNIX_STREAM,
                invalidUnixAddress, "/var/run/dst.sock", 0, 0));
    }

    @Test
    public void testNullUnixAddress() {
        assertThrows(NullPointerException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.UNIX_STREAM,
                null, null, 0, 0));
    }

    @Test
    public void testLongUnixAddress() {
        String longUnixAddress = new String(new char[109]).replace("\0", "a");
        assertThrows(IllegalArgumentException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.UNIX_STREAM,
                "source", longUnixAddress, 0, 0));
    }

    @Test
    public void testInvalidUnixPort() {
        assertThrows(IllegalArgumentException.class, () -> new HAProxyMessage(
                HAProxyProtocolVersion.V2, HAProxyCommand.PROXY, HAProxyProxiedProtocol.UNIX_STREAM,
                "/var/run/src.sock", "/var/run/dst.sock", 80, 443));
    }
}
