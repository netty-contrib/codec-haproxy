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
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.handler.codec.MessageToByteEncoder;
import java.nio.charset.StandardCharsets;
import io.netty5.util.NetUtil;

import java.util.List;

import static io.netty.contrib.handler.codec.haproxy.HAProxyConstants.*;

/**
 * Encodes an HAProxy proxy protocol message
 *
 * @see <a href="https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt">Proxy Protocol Specification</a>
 */
public final class HAProxyMessageEncoder extends MessageToByteEncoder<HAProxyMessage> {

    private static final int V2_VERSION_BITMASK = 0x02 << 4;

    // Length for source/destination addresses for the UNIX family must be 108 bytes each.
    static final int UNIX_ADDRESS_BYTES_LENGTH = 108;
    static final int TOTAL_UNIX_ADDRESS_BYTES_LENGTH = UNIX_ADDRESS_BYTES_LENGTH * 2;

    public static final HAProxyMessageEncoder INSTANCE = new HAProxyMessageEncoder();

    private HAProxyMessageEncoder() {
    }

    @Override
    protected Buffer allocateBuffer(ChannelHandlerContext ctx, HAProxyMessage msg) {
        return ctx.bufferAllocator().allocate(256);
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, HAProxyMessage msg, Buffer out) {
        switch (msg.protocolVersion()) {
            case V1:
                encodeV1(msg, out);
                break;
            case V2:
                encodeV2(msg, out);
                break;
            default:
                throw new HAProxyProtocolException("Unsupported version: " + msg.protocolVersion());
        }
    }

    private static void encodeV1(HAProxyMessage msg, Buffer out) {
        out.writeBytes(TEXT_PREFIX);
        out.writeByte((byte) ' ');
        out.writeCharSequence(msg.proxiedProtocol().name(), StandardCharsets.US_ASCII);
        out.writeByte((byte) ' ');
        out.writeCharSequence(msg.sourceAddress(), StandardCharsets.US_ASCII);
        out.writeByte((byte) ' ');
        out.writeCharSequence(msg.destinationAddress(), StandardCharsets.US_ASCII);
        out.writeByte((byte) ' ');
        out.writeCharSequence(String.valueOf(msg.sourcePort()), StandardCharsets.US_ASCII);
        out.writeByte((byte) ' ');
        out.writeCharSequence(String.valueOf(msg.destinationPort()), StandardCharsets.US_ASCII);
        out.writeByte((byte) '\r');
        out.writeByte((byte) '\n');
    }

    private static void encodeV2(HAProxyMessage msg, Buffer out) {
        out.writeBytes(BINARY_PREFIX);
        out.writeByte((byte) (V2_VERSION_BITMASK | msg.command().byteValue()));
        out.writeByte(msg.proxiedProtocol().byteValue());

        switch (msg.proxiedProtocol().addressFamily()) {
            case AF_IPv4:
            case AF_IPv6:
                byte[] srcAddrBytes = NetUtil.createByteArrayFromIpAddressString(msg.sourceAddress());
                byte[] dstAddrBytes = NetUtil.createByteArrayFromIpAddressString(msg.destinationAddress());
                // srcAddrLen + dstAddrLen + 4 (srcPort + dstPort) + numTlvBytes
                out.writeShort((short) (srcAddrBytes.length + dstAddrBytes.length + 4 + msg.tlvNumBytes()));
                out.writeBytes(srcAddrBytes);
                out.writeBytes(dstAddrBytes);
                out.writeShort((short) msg.sourcePort());
                out.writeShort((short) msg.destinationPort());
                encodeTlvs(msg.tlvs(), out);
                break;
            case AF_UNIX:
                out.writeShort((short) (TOTAL_UNIX_ADDRESS_BYTES_LENGTH + msg.tlvNumBytes()));
                int srcAddrBytesWritten = out.writerOffset();
                out.writeCharSequence(msg.sourceAddress(), StandardCharsets.US_ASCII);
                srcAddrBytesWritten = out.writerOffset() - srcAddrBytesWritten;
                int length = UNIX_ADDRESS_BYTES_LENGTH - srcAddrBytesWritten;
                for(int i = 0; i < length; ++i) {
                    out.writeByte((byte) 0);
                }
                int dstAddrBytesWritten = out.writerOffset();
                out.writeCharSequence(msg.destinationAddress(), StandardCharsets.US_ASCII);
                dstAddrBytesWritten = out.writerOffset() - dstAddrBytesWritten;
                length = UNIX_ADDRESS_BYTES_LENGTH - dstAddrBytesWritten;
                for(int i = 0; i < length; ++i) {
                    out.writeByte((byte) 0);
                }
                encodeTlvs(msg.tlvs(), out);
                break;
            case AF_UNSPEC:
                out.writeShort((short) 0);
                break;
            default:
                throw new HAProxyProtocolException("unexpected addrFamily");
        }
    }

    private static void encodeTlv(HAProxyTLV haProxyTLV, Buffer out) {
        if (haProxyTLV instanceof HAProxySSLTLV) {
            HAProxySSLTLV ssltlv = (HAProxySSLTLV) haProxyTLV;
            out.writeByte(haProxyTLV.typeByteValue());
            out.writeShort((short) ssltlv.contentNumBytes());
            out.writeByte(ssltlv.client());
            out.writeInt(ssltlv.verify());
            encodeTlvs(ssltlv.encapsulatedTLVs(), out);
        } else {
            out.writeByte(haProxyTLV.typeByteValue());
            Buffer value = haProxyTLV.content();
            int readableBytes = value.readableBytes();
            out.writeShort((short) readableBytes);
            value.copyInto(value.readerOffset(), out, out.writerOffset(), readableBytes);
            out.skipWritableBytes(readableBytes);
        }
    }

    private static void encodeTlvs(List<HAProxyTLV> haProxyTLVs, Buffer out) {
        for (int i = 0; i < haProxyTLVs.size(); i++) {
            encodeTlv(haProxyTLVs.get(i), out);
        }
    }

    @Override
    public boolean isSharable() {
        return true;
    }
}
