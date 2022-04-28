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

import io.netty5.bootstrap.Bootstrap;
import io.netty5.bootstrap.ServerBootstrap;
import io.netty5.buffer.api.Send;
import io.netty5.channel.Channel;
import io.netty5.channel.ChannelHandlerContext;
import io.netty5.channel.ChannelInitializer;
import io.netty5.channel.EventLoopGroup;
import io.netty5.channel.MultithreadEventLoopGroup;
import io.netty5.channel.SimpleChannelInboundHandler;
import io.netty5.channel.local.LocalAddress;
import io.netty5.channel.local.LocalChannel;
import io.netty5.channel.local.LocalHandler;
import io.netty5.channel.local.LocalServerChannel;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HAProxyIntegrationTest {

    @Test
    public void testBasicCase() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Send<HAProxyMessage>> msgHolder = new AtomicReference<>();
        LocalAddress localAddress = new LocalAddress("HAProxyIntegrationTest");

        EventLoopGroup group = new MultithreadEventLoopGroup(LocalHandler.newFactory());
        ServerBootstrap sb = new ServerBootstrap();
        sb.channel(LocalServerChannel.class)
          .group(group)
          .childHandler(new ChannelInitializer<>() {
              @Override
              protected void initChannel(Channel ch) {
                  ch.pipeline().addLast(new HAProxyMessageDecoder());
                  ch.pipeline().addLast(new SimpleChannelInboundHandler<HAProxyMessage>() {
                      @Override
                      protected void messageReceived(ChannelHandlerContext ctx, HAProxyMessage msg) {
                          msgHolder.set(msg.send());
                          latch.countDown();
                      }
                  });
              }
          });
        Channel serverChannel = sb.bind(localAddress).get();

        Bootstrap b = new Bootstrap();
        Channel clientChannel = b.channel(LocalChannel.class)
                                 .handler(HAProxyMessageEncoder.INSTANCE)
                                 .group(group)
                                 .connect(localAddress).get();

        try {
            HAProxyMessage message = new HAProxyMessage(
                    HAProxyProtocolVersion.V1, HAProxyCommand.PROXY, HAProxyProxiedProtocol.TCP4,
                    "192.168.0.1", "192.168.0.11", 56324, 443);
            clientChannel.writeAndFlush(message).sync();

            assertTrue(latch.await(5, TimeUnit.SECONDS));
            try (HAProxyMessage readMessage = msgHolder.get().receive()) {
                assertEquals(message.protocolVersion(), readMessage.protocolVersion());
                assertEquals(message.command(), readMessage.command());
                assertEquals(message.proxiedProtocol(), readMessage.proxiedProtocol());
                assertEquals(message.sourceAddress(), readMessage.sourceAddress());
                assertEquals(message.destinationAddress(), readMessage.destinationAddress());
                assertEquals(message.sourcePort(), readMessage.sourcePort());
                assertEquals(message.destinationPort(), readMessage.destinationPort());
            }
        } finally {
            clientChannel.close().sync();
            serverChannel.close().sync();
            group.shutdownGracefully().sync();
        }
    }
}
