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

import io.netty5.channel.ChannelHandler;
import io.netty5.channel.ChannelHandlerContext;
import io.netty.contrib.handler.codec.haproxy.HAProxyMessage;
import io.netty.contrib.handler.codec.haproxy.HAProxyMessageEncoder;
import io.netty5.util.concurrent.Future;

public class HAProxyHandler implements ChannelHandler {

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        ctx.pipeline().addBefore(ctx.name(), null, HAProxyMessageEncoder.INSTANCE);
    }

    @Override
    public Future<Void> write(final ChannelHandlerContext ctx, Object msg) {
        Future<Void> future = ctx.write(msg);
        if (msg instanceof HAProxyMessage) {
            future.addListener(fut -> {
                if (fut.isSuccess()) {
                    ctx.pipeline().remove(HAProxyMessageEncoder.INSTANCE);
                    ctx.pipeline().remove(this);
                } else {
                    ctx.close();
                }
            });
        }
        return future;
    }
}
