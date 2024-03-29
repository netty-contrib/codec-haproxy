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
import io.netty5.channel.embedded.EmbeddedChannel;
import io.netty5.handler.codec.ProtocolDetectionResult;
import io.netty5.handler.codec.ProtocolDetectionState;
import io.netty.contrib.handler.codec.haproxy.HAProxyProxiedProtocol.AddressFamily;
import io.netty.contrib.handler.codec.haproxy.HAProxyProxiedProtocol.TransportProtocol;
import java.nio.charset.StandardCharsets;
import io.netty5.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static io.netty5.buffer.BufferUtil.writeAscii;
import static io.netty5.buffer.DefaultBufferAllocators.preferredAllocator;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class HAProxyMessageDecoderTest {
    private EmbeddedChannel ch;

    @BeforeEach
    public void setUp() {
        ch = new EmbeddedChannel(new HAProxyMessageDecoder());
    }

    @Test
    public void testIPV4Decode() {
        int startChannels = ch.pipeline().names().size();
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        ch.writeInbound(writeAscii(ch.bufferAllocator(), header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V1, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.TCP4, msg.proxiedProtocol());
            assertEquals("192.168.0.1", msg.sourceAddress());
            assertEquals("192.168.0.11", msg.destinationAddress());
            assertEquals(56324, msg.sourcePort());
            assertEquals(443, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testIPV6Decode() {
        int startChannels = ch.pipeline().names().size();
        String header = "PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 1050:0:0:0:5:600:300c:326b 56324 443\r\n";
        ch.writeInbound(writeAscii(ch.bufferAllocator(), header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V1, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.TCP6, msg.proxiedProtocol());
            assertEquals("2001:0db8:85a3:0000:0000:8a2e:0370:7334", msg.sourceAddress());
            assertEquals("1050:0:0:0:5:600:300c:326b", msg.destinationAddress());
            assertEquals(56324, msg.sourcePort());
            assertEquals(443, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testUnknownProtocolDecode() {
        int startChannels = ch.pipeline().names().size();
        String header = "PROXY UNKNOWN 192.168.0.1 192.168.0.11 56324 443\r\n";
        ch.writeInbound(writeAscii(ch.bufferAllocator(), header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V1, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.UNKNOWN, msg.proxiedProtocol());
            assertNull(msg.sourceAddress());
            assertNull(msg.destinationAddress());
            assertEquals(0, msg.sourcePort());
            assertEquals(0, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV1NoUDP() {
        String header = "PROXY UDP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidPort() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 80000 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidIPV4Address() {
        String header = "PROXY TCP4 299.168.0.1 192.168.0.11 56324 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidIPV6Address() {
        String header = "PROXY TCP6 r001:0db8:85a3:0000:0000:8a2e:0370:7334 1050:0:0:0:5:600:300c:326b 56324 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidProtocol() {
        String header = "PROXY TCP7 192.168.0.1 192.168.0.11 56324 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testMissingParams() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testTooManyParams() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443 123\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidCommand() {
        String header = "PING TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testInvalidEOL() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\nGET / HTTP/1.1\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testHeaderTooLong() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 " +
                        "00000000000000000000000000000000000000000000000000000000000000000443\r\n";
        assertThrows(HAProxyProtocolException.class,
            () -> ch.writeInbound(writeAscii(ch.bufferAllocator(), header)));
    }

    @Test
    public void testFailSlowHeaderTooLong() {
        EmbeddedChannel slowFailCh = new EmbeddedChannel(new HAProxyMessageDecoder(false));
        try {
            String headerPart1 = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 " +
                                 "000000000000000000000000000000000000000000000000000000000000000000000443";
            // Should not throw exception
            assertFalse(slowFailCh.writeInbound(writeAscii(ch.bufferAllocator(), headerPart1)));
            String headerPart2 = "more header data";
            // Should not throw exception
            assertFalse(slowFailCh.writeInbound(writeAscii(ch.bufferAllocator(), headerPart2)));
            String headerPart3 = "end of header\r\n";

            int discarded = headerPart1.length() + headerPart2.length() + headerPart3.length() - 2;
            assertThrows(HAProxyProtocolException.class,
                () -> slowFailCh.writeInbound(writeAscii(ch.bufferAllocator(), headerPart3)), "over " + discarded);
        } finally {
            assertFalse(slowFailCh.finishAndReleaseAll());
        }
    }

    @Test
    public void testFailFastHeaderTooLong() {
        EmbeddedChannel fastFailCh = new EmbeddedChannel(new HAProxyMessageDecoder(true));
        try {
            String headerPart1 = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 " +
                                 "000000000000000000000000000000000000000000000000000000000000000000000443";
            assertThrows(HAProxyProtocolException.class,
                () -> fastFailCh.writeInbound(writeAscii(ch.bufferAllocator(), headerPart1)),
                "over " + headerPart1.length());
        } finally {
            assertFalse(fastFailCh.finishAndReleaseAll());
        }
    }

    @Test
    public void testIncompleteHeader() {
        String header = "PROXY TCP4 192.168.0.1 192.168.0.11 56324";
        ch.writeInbound(writeAscii(ch.bufferAllocator(), header));
        assertNull(ch.readInbound());
        assertFalse(ch.finish());
    }

    @Test
    public void testCloseOnInvalid() throws InterruptedException {
        Future<Void> closeFuture = ch.closeFuture();
        String header = "GET / HTTP/1.1\r\n";
        try {
            ch.writeInbound(writeAscii(ch.bufferAllocator(), header));
        } catch (HAProxyProtocolException ppex) {
            // swallow this exception since we're just testing to be sure the channel was closed
        }
        boolean isComplete = closeFuture.asStage().await(5000, TimeUnit.MILLISECONDS);
        if (!isComplete || !closeFuture.isDone() || closeFuture.isFailed()) {
            fail("Expected channel close");
        }
    }

    @Test
    public void testTransportProtocolAndAddressFamily() {
        final byte unknown = HAProxyProxiedProtocol.UNKNOWN.byteValue();
        final byte tcp4 = HAProxyProxiedProtocol.TCP4.byteValue();
        final byte tcp6 = HAProxyProxiedProtocol.TCP6.byteValue();
        final byte udp4 = HAProxyProxiedProtocol.UDP4.byteValue();
        final byte udp6 = HAProxyProxiedProtocol.UDP6.byteValue();
        final byte unix_stream = HAProxyProxiedProtocol.UNIX_STREAM.byteValue();
        final byte unix_dgram = HAProxyProxiedProtocol.UNIX_DGRAM.byteValue();

        assertEquals(TransportProtocol.UNSPEC, TransportProtocol.valueOf(unknown));
        assertEquals(TransportProtocol.STREAM, TransportProtocol.valueOf(tcp4));
        assertEquals(TransportProtocol.STREAM, TransportProtocol.valueOf(tcp6));
        assertEquals(TransportProtocol.STREAM, TransportProtocol.valueOf(unix_stream));
        assertEquals(TransportProtocol.DGRAM, TransportProtocol.valueOf(udp4));
        assertEquals(TransportProtocol.DGRAM, TransportProtocol.valueOf(udp6));
        assertEquals(TransportProtocol.DGRAM, TransportProtocol.valueOf(unix_dgram));

        assertEquals(AddressFamily.AF_UNSPEC, AddressFamily.valueOf(unknown));
        assertEquals(AddressFamily.AF_IPv4, AddressFamily.valueOf(tcp4));
        assertEquals(AddressFamily.AF_IPv4, AddressFamily.valueOf(udp4));
        assertEquals(AddressFamily.AF_IPv6, AddressFamily.valueOf(tcp6));
        assertEquals(AddressFamily.AF_IPv6, AddressFamily.valueOf(udp6));
        assertEquals(AddressFamily.AF_UNIX, AddressFamily.valueOf(unix_stream));
        assertEquals(AddressFamily.AF_UNIX, AddressFamily.valueOf(unix_dgram));
    }

    @Test
    public void testV2IPV4Decode() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x11; // TCP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.TCP4, msg.proxiedProtocol());
            assertEquals("192.168.0.1", msg.sourceAddress());
            assertEquals("192.168.0.11", msg.destinationAddress());
            assertEquals(56324, msg.sourcePort());
            assertEquals(443, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV2UDPDecode() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x12; // UDP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.UDP4, msg.proxiedProtocol());
            assertEquals("192.168.0.1", msg.sourceAddress());
            assertEquals("192.168.0.11", msg.destinationAddress());
            assertEquals(56324, msg.sourcePort());
            assertEquals(443, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testv2IPV6Decode() {
        byte[] header = new byte[52];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x21; // TCP over IPv6

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x24; // -----

        header[16] = 0x20; // Source Address
        header[17] = 0x01; // -----
        header[18] = 0x0d; // -----
        header[19] = (byte) 0xb8; // -----
        header[20] = (byte) 0x85; // -----
        header[21] = (byte) 0xa3; // -----
        header[22] = 0x00; // -----
        header[23] = 0x00; // -----
        header[24] = 0x00; // -----
        header[25] = 0x00; // -----
        header[26] = (byte) 0x8a; // -----
        header[27] = 0x2e; // -----
        header[28] = 0x03; // -----
        header[29] = 0x70; // -----
        header[30] = 0x73; // -----
        header[31] = 0x34; // -----

        header[32] = 0x10; // Destination Address
        header[33] = 0x50; // -----
        header[34] = 0x00; // -----
        header[35] = 0x00; // -----
        header[36] = 0x00; // -----
        header[37] = 0x00; // -----
        header[38] = 0x00; // -----
        header[39] = 0x00; // -----
        header[40] = 0x00; // -----
        header[41] = 0x05; // -----
        header[42] = 0x06; // -----
        header[43] = 0x00; // -----
        header[44] = 0x30; // -----
        header[45] = 0x0c; // -----
        header[46] = 0x32; // -----
        header[47] = 0x6b; // -----

        header[48] = (byte) 0xdc; // Source Port
        header[49] = 0x04; // -----

        header[50] = 0x01; // Destination Port
        header[51] = (byte) 0xbb; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.TCP6, msg.proxiedProtocol());
            assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", msg.sourceAddress());
            assertEquals("1050:0:0:0:5:600:300c:326b", msg.destinationAddress());
            assertEquals(56324, msg.sourcePort());
            assertEquals(443, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testv2UnixDecode() {
        byte[] header = new byte[232];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x31; // UNIX_STREAM

        header[14] = 0x00; // Remaining Bytes
        header[15] = (byte) 0xd8; // -----

        header[16] = 0x2f; // Source Address
        header[17] = 0x76; // -----
        header[18] = 0x61; // -----
        header[19] = 0x72; // -----
        header[20] = 0x2f; // -----
        header[21] = 0x72; // -----
        header[22] = 0x75; // -----
        header[23] = 0x6e; // -----
        header[24] = 0x2f; // -----
        header[25] = 0x73; // -----
        header[26] = 0x72; // -----
        header[27] = 0x63; // -----
        header[28] = 0x2e; // -----
        header[29] = 0x73; // -----
        header[30] = 0x6f; // -----
        header[31] = 0x63; // -----
        header[32] = 0x6b; // -----
        header[33] = 0x00; // -----

        header[124] = 0x2f; // Destination Address
        header[125] = 0x76; // -----
        header[126] = 0x61; // -----
        header[127] = 0x72; // -----
        header[128] = 0x2f; // -----
        header[129] = 0x72; // -----
        header[130] = 0x75; // -----
        header[131] = 0x6e; // -----
        header[132] = 0x2f; // -----
        header[133] = 0x64; // -----
        header[134] = 0x65; // -----
        header[135] = 0x73; // -----
        header[136] = 0x74; // -----
        header[137] = 0x2e; // -----
        header[138] = 0x73; // -----
        header[139] = 0x6f; // -----
        header[140] = 0x63; // -----
        header[141] = 0x6b; // -----
        header[142] = 0x00; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.UNIX_STREAM, msg.proxiedProtocol());
            assertEquals("/var/run/src.sock", msg.sourceAddress());
            assertEquals("/var/run/dest.sock", msg.destinationAddress());
            assertEquals(0, msg.sourcePort());
            assertEquals(0, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV2LocalProtocolDecode() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x20; // v2, cmd=LOCAL
        header[13] = 0x00; // Unspecified transport protocol and address family

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.LOCAL, msg.command());
            assertEquals(HAProxyProxiedProtocol.UNKNOWN, msg.proxiedProtocol());
            assertNull(msg.sourceAddress());
            assertNull(msg.destinationAddress());
            assertEquals(0, msg.sourcePort());
            assertEquals(0, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV2UnknownProtocolDecode() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x00; // Unspecified transport protocol and address family

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.UNKNOWN, msg.proxiedProtocol());
            assertNull(msg.sourceAddress());
            assertNull(msg.destinationAddress());
            assertEquals(0, msg.sourcePort());
            assertEquals(0, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV2WithSslTLVs() {
        ch = new EmbeddedChannel(new HAProxyMessageDecoder());

        final byte[] bytes = {
                13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 35, 127, 0, 0, 1, 127, 0, 0, 1,
                -55, -90, 7, 89, 32, 0, 20, 5, 0, 0, 0, 0, 33, 0, 5, 84, 76, 83, 118, 49, 34, 0, 4, 76, 69, 65, 70
        };

        int startChannels = ch.pipeline().names().size();
        assertTrue(ch.writeInbound(ch.bufferAllocator().copyOf(bytes)));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.TCP4, msg.proxiedProtocol());
            assertEquals("127.0.0.1", msg.sourceAddress());
            assertEquals("127.0.0.1", msg.destinationAddress());
            assertEquals(51622, msg.sourcePort());
            assertEquals(1881, msg.destinationPort());
            final List<HAProxyTLV> tlvs = msg.tlvs();

            assertEquals(3, tlvs.size());
            final HAProxyTLV firstTlv = tlvs.get(0);
            assertEquals(HAProxyTLV.Type.PP2_TYPE_SSL, firstTlv.type());
            final HAProxySSLTLV sslTlv = (HAProxySSLTLV) firstTlv;
            assertEquals(0, sslTlv.verify());
            assertTrue(sslTlv.isPP2ClientSSL());
            assertTrue(sslTlv.isPP2ClientCertSess());
            assertFalse(sslTlv.isPP2ClientCertConn());

            final HAProxyTLV secondTlv = tlvs.get(1);

            assertEquals(HAProxyTLV.Type.PP2_TYPE_SSL_VERSION, secondTlv.type());
            Buffer secondContentBuf = secondTlv.content();
            byte[] secondContent = new byte[secondContentBuf.readableBytes()];
            secondContentBuf.readBytes(secondContent, 0, secondContent.length);
            assertArrayEquals("TLSv1".getBytes(StandardCharsets.US_ASCII), secondContent);

            final HAProxyTLV thirdTLV = tlvs.get(2);
            assertEquals(HAProxyTLV.Type.PP2_TYPE_SSL_CN, thirdTLV.type());
            Buffer thirdContentBuf = thirdTLV.content();
            byte[] thirdContent = new byte[thirdContentBuf.readableBytes()];
            thirdContentBuf.readBytes(thirdContent, 0, thirdContent.length);
            assertArrayEquals("LEAF".getBytes(StandardCharsets.US_ASCII), thirdContent);

            assertTrue(sslTlv.encapsulatedTLVs().contains(secondTlv));
            assertTrue(sslTlv.encapsulatedTLVs().contains(thirdTLV));
        }
        assertNull(ch.readInbound());
        assertFalse(ch.finish());
    }

    @Test
    public void testV2WithTLV() {
        ch = new EmbeddedChannel(new HAProxyMessageDecoder(4));

        byte[] header = new byte[236];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x31; // UNIX_STREAM

        header[14] = 0x00; // Remaining Bytes
        header[15] = (byte) 0xdc; // -----

        header[16] = 0x2f; // Source Address
        header[17] = 0x76; // -----
        header[18] = 0x61; // -----
        header[19] = 0x72; // -----
        header[20] = 0x2f; // -----
        header[21] = 0x72; // -----
        header[22] = 0x75; // -----
        header[23] = 0x6e; // -----
        header[24] = 0x2f; // -----
        header[25] = 0x73; // -----
        header[26] = 0x72; // -----
        header[27] = 0x63; // -----
        header[28] = 0x2e; // -----
        header[29] = 0x73; // -----
        header[30] = 0x6f; // -----
        header[31] = 0x63; // -----
        header[32] = 0x6b; // -----
        header[33] = 0x00; // -----

        header[124] = 0x2f; // Destination Address
        header[125] = 0x76; // -----
        header[126] = 0x61; // -----
        header[127] = 0x72; // -----
        header[128] = 0x2f; // -----
        header[129] = 0x72; // -----
        header[130] = 0x75; // -----
        header[131] = 0x6e; // -----
        header[132] = 0x2f; // -----
        header[133] = 0x64; // -----
        header[134] = 0x65; // -----
        header[135] = 0x73; // -----
        header[136] = 0x74; // -----
        header[137] = 0x2e; // -----
        header[138] = 0x73; // -----
        header[139] = 0x6f; // -----
        header[140] = 0x63; // -----
        header[141] = 0x6b; // -----
        header[142] = 0x00; // -----

        // ---- Additional data (TLV) ---- \\

        header[232] = 0x01; // Type
        header[233] = 0x00; // Remaining bytes
        header[234] = 0x01; // -----
        header[235] = 0x01; // Payload

        int startChannels = ch.pipeline().names().size();
        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        Object msgObj = ch.readInbound();
        assertEquals(startChannels - 1, ch.pipeline().names().size());
        assertTrue(msgObj instanceof HAProxyMessage);
        try (HAProxyMessage msg = (HAProxyMessage) msgObj) {
            assertEquals(HAProxyProtocolVersion.V2, msg.protocolVersion());
            assertEquals(HAProxyCommand.PROXY, msg.command());
            assertEquals(HAProxyProxiedProtocol.UNIX_STREAM, msg.proxiedProtocol());
            assertEquals("/var/run/src.sock", msg.sourceAddress());
            assertEquals("/var/run/dest.sock", msg.destinationAddress());
            assertEquals(0, msg.sourcePort());
            assertEquals(0, msg.destinationPort());
            assertNull(ch.readInbound());
            assertFalse(ch.finish());
        }
    }

    @Test
    public void testV2InvalidProtocol() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x41; // Bogus transport protocol

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        assertThrows(HAProxyProtocolException.class, () -> ch.writeInbound(ch.bufferAllocator().copyOf(header)));
    }

    @Test
    public void testV2MissingParams() {
        byte[] header = new byte[26];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x11; // TCP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0a; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        assertThrows(HAProxyProtocolException.class, () -> ch.writeInbound(ch.bufferAllocator().copyOf(header)));
    }

    @Test
    public void testV2InvalidCommand() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x22; // v2, Bogus command
        header[13] = 0x11; // TCP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        assertThrows(HAProxyProtocolException.class, () -> ch.writeInbound(ch.bufferAllocator().copyOf(header)));
    }

    @Test
    public void testV2InvalidVersion() {
        byte[] header = new byte[28];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x31; // Bogus version, cmd=PROXY
        header[13] = 0x11; // TCP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = 0x0c; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        assertThrows(HAProxyProtocolException.class, () -> ch.writeInbound(ch.bufferAllocator().copyOf(header)));
    }

    @Test
    public void testV2HeaderTooLong() {
        ch = new EmbeddedChannel(new HAProxyMessageDecoder(0));

        byte[] header = new byte[248];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY
        header[13] = 0x11; // TCP over IPv4

        header[14] = 0x00; // Remaining Bytes
        header[15] = (byte) 0xe8; // -----

        header[16] = (byte) 0xc0; // Source Address
        header[17] = (byte) 0xa8; // -----
        header[18] = 0x00; // -----
        header[19] = 0x01; // -----

        header[20] = (byte) 0xc0; // Destination Address
        header[21] = (byte) 0xa8; // -----
        header[22] = 0x00; // -----
        header[23] = 0x0b; // -----

        header[24] = (byte) 0xdc; // Source Port
        header[25] = 0x04; // -----

        header[26] = 0x01; // Destination Port
        header[27] = (byte) 0xbb; // -----

        assertThrows(HAProxyProtocolException.class, () -> ch.writeInbound(ch.bufferAllocator().copyOf(header)));
    }

    @Test
    public void testV2IncompleteHeader() {
        byte[] header = new byte[13];
        header[0] = 0x0D; // Binary Prefix
        header[1] = 0x0A; // -----
        header[2] = 0x0D; // -----
        header[3] = 0x0A; // -----
        header[4] = 0x00; // -----
        header[5] = 0x0D; // -----
        header[6] = 0x0A; // -----
        header[7] = 0x51; // -----
        header[8] = 0x55; // -----
        header[9] = 0x49; // -----
        header[10] = 0x54; // -----
        header[11] = 0x0A; // -----

        header[12] = 0x21; // v2, cmd=PROXY

        ch.writeInbound(ch.bufferAllocator().copyOf(header));
        assertNull(ch.readInbound());
        assertFalse(ch.finish());
    }

    @Test
    public void testDetectProtocol() {
        ProtocolDetectionResult<HAProxyProtocolVersion> result;
        try (Buffer validHeaderV1 = writeAscii(preferredAllocator(),
                "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")) {
            result = HAProxyMessageDecoder.detectProtocol(validHeaderV1);
            assertEquals(ProtocolDetectionState.DETECTED, result.state());
            assertEquals(HAProxyProtocolVersion.V1, result.detectedProtocol());
        }

        try (Buffer invalidHeader = writeAscii(preferredAllocator(), "Invalid header")) {
            result = HAProxyMessageDecoder.detectProtocol(invalidHeader);
            assertEquals(ProtocolDetectionState.INVALID, result.state());
            assertNull(result.detectedProtocol());
        }

        try (Buffer validHeaderV2 = preferredAllocator().allocate(12)) {
            validHeaderV2.writeByte((byte) 0x0D);
            validHeaderV2.writeByte((byte) 0x0A);
            validHeaderV2.writeByte((byte) 0x0D);
            validHeaderV2.writeByte((byte) 0x0A);
            validHeaderV2.writeByte((byte) 0x00);
            validHeaderV2.writeByte((byte) 0x0D);
            validHeaderV2.writeByte((byte) 0x0A);
            validHeaderV2.writeByte((byte) 0x51);
            validHeaderV2.writeByte((byte) 0x55);
            validHeaderV2.writeByte((byte) 0x49);
            validHeaderV2.writeByte((byte) 0x54);
            validHeaderV2.writeByte((byte) 0x0A);
            result = HAProxyMessageDecoder.detectProtocol(validHeaderV2);
            assertEquals(ProtocolDetectionState.DETECTED, result.state());
            assertEquals(HAProxyProtocolVersion.V2, result.detectedProtocol());
        }

        try (Buffer incompleteHeader = preferredAllocator().allocate(7)) {
            incompleteHeader.writeByte((byte) 0x0D);
            incompleteHeader.writeByte((byte) 0x0A);
            incompleteHeader.writeByte((byte) 0x0D);
            incompleteHeader.writeByte((byte) 0x0A);
            incompleteHeader.writeByte((byte) 0x00);
            incompleteHeader.writeByte((byte) 0x0D);
            incompleteHeader.writeByte((byte) 0x0A);
            result = HAProxyMessageDecoder.detectProtocol(incompleteHeader);
            assertEquals(ProtocolDetectionState.NEEDS_MORE_DATA, result.state());
            assertNull(result.detectedProtocol());
        }
    }
}
