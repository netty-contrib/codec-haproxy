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

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static io.netty5.buffer.DefaultBufferAllocators.preferredAllocator;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HAProxySSLTLVTest {

    @Test
    public void testClientBitmask() {

        // 0b0000_0111
        final byte allClientsEnabled = 0x7;
        try (HAProxySSLTLV allClientsEnabledTLV = new HAProxySSLTLV(0, allClientsEnabled,
                Collections.emptyList(), preferredAllocator().allocate(0))) {
            assertTrue(allClientsEnabledTLV.isPP2ClientCertConn());
            assertTrue(allClientsEnabledTLV.isPP2ClientSSL());
            assertTrue(allClientsEnabledTLV.isPP2ClientCertSess());
        }

        // 0b0000_0101
        final byte clientSSLandClientCertSessEnabled = 0x5;
        try (HAProxySSLTLV clientSSLandClientCertSessTLV = new HAProxySSLTLV(0, clientSSLandClientCertSessEnabled,
                Collections.emptyList(), preferredAllocator().allocate(0))) {
            assertFalse(clientSSLandClientCertSessTLV.isPP2ClientCertConn());
            assertTrue(clientSSLandClientCertSessTLV.isPP2ClientSSL());
            assertTrue(clientSSLandClientCertSessTLV.isPP2ClientCertSess());
        }

        // 0b0000_0000
        final byte noClientEnabled = 0x0;
        try (HAProxySSLTLV noClientTlv = new HAProxySSLTLV(0, noClientEnabled, Collections.emptyList(),
                preferredAllocator().allocate(0))) {
            assertFalse(noClientTlv.isPP2ClientCertConn());
            assertFalse(noClientTlv.isPP2ClientSSL());
            assertFalse(noClientTlv.isPP2ClientCertSess());
        }
    }
}
