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
package io.netty.contrib.handler.codec.haproxy.example;

import io.netty5.bootstrap.ServerBootstrap;
import io.netty5.buffer.api.Buffer;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.ChannelInitializer;
import io.netty5.channel.EventLoopGroup;
import io.netty5.channel.MultithreadEventLoopGroup;
import io.netty5.channel.SimpleChannelInboundHandler;
import io.netty5.channel.nio.NioHandler;
import io.netty5.channel.socket.SocketChannel;
import io.netty5.channel.socket.nio.NioServerSocketChannel;
import io.netty.contrib.handler.codec.haproxy.HAProxyMessage;
import io.netty.contrib.handler.codec.haproxy.HAProxyMessageDecoder;
import io.netty5.handler.logging.LogLevel;
import io.netty5.handler.logging.LoggingHandler;

import static io.netty5.buffer.BufferUtil.appendPrettyHexDump;

public final class HAProxyServer {

    static final int PORT = Integer.parseInt(System.getProperty("port", "8080"));

    public static void main(String[] args) throws Exception {
        EventLoopGroup bossGroup = new MultithreadEventLoopGroup(1, NioHandler.newFactory());
        EventLoopGroup workerGroup = new MultithreadEventLoopGroup(NioHandler.newFactory());
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             .handler(new LoggingHandler(LogLevel.INFO))
             .childHandler(new HAProxyServerInitializer());
            b.bind(PORT).get().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    static class HAProxyServerInitializer extends ChannelInitializer<SocketChannel> {
        @Override
        public void initChannel(SocketChannel ch) {
            ch.pipeline().addLast(
                    new LoggingHandler(LogLevel.DEBUG),
                    new HAProxyMessageDecoder(),
                    new SimpleChannelInboundHandler<>() {
                        @Override
                        protected void messageReceived(ChannelHandlerContext ctx, Object msg) {
                            if (msg instanceof HAProxyMessage) {
                                System.out.println("proxy message: " + msg);
                            } else if (msg instanceof Buffer) {
                                Buffer buffer = (Buffer) msg;
                                int length = buffer.readableBytes();
                                int rows = length / 16 + ((length & 15) == 0? 0 : 1) + 4;
                                StringBuilder stringBuilder = new StringBuilder(rows * 80);
                                appendPrettyHexDump(stringBuilder, buffer, buffer.readerOffset(), length);
                                System.out.println("buffer message: " + stringBuilder);
                            }
                        }
                    });
        }
    }
}
