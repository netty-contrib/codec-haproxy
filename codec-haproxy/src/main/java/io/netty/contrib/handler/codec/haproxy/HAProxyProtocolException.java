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

import io.netty5.handler.codec.DecoderException;

/**
 * A {@link DecoderException} which is thrown when an invalid HAProxy proxy protocol header is encountered
 */
public class HAProxyProtocolException extends DecoderException {

    private static final long serialVersionUID = 713710864325167351L;

    /**
     * Creates a new instance
     */
    public HAProxyProtocolException() { }

    /**
     * Creates a new instance
     */
    public HAProxyProtocolException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new instance
     */
    public HAProxyProtocolException(String message) {
        super(message);
    }

    /**
     * Creates a new instance
     */
    public HAProxyProtocolException(Throwable cause) {
        super(cause);
    }
}
