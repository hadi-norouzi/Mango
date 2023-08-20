import Foundation

extension MGConfiguration {
    
    struct URLComponents {
        
        let protocolType: MGConfiguration.Outbound.ProtocolType
        let user: String
        let host: String
        let port: Int
        let queryMapping: [String: String]
        let transport: MGConfiguration.Outbound.StreamSettings.Transport
        let security: MGConfiguration.Outbound.StreamSettings.Security
        let descriptive: String
        
        init(urlString: String) throws {
            guard let components = Foundation.URLComponents(string: urlString),
                  let protocolType = components.scheme.flatMap(MGConfiguration.Outbound.ProtocolType.init(rawValue:)) else {
                throw NSError.newError("Protocol link parsing failed")
            }
            guard protocolType == .vless || protocolType == .vmess else {
                throw NSError.newError("protocol analysis\(protocolType.description)Not supported yet")
            }
            guard let user = components.user, !user.isEmpty else {
                throw NSError.newError("User does not exist")
            }
            guard let host = components.host, !host.isEmpty else {
                throw NSError.newError("The server domain name or address does not exist")
            }
            guard let port = components.port, (1...65535).contains(port) else {
                throw NSError.newError("The port number of the server is invalid")
            }
            let mapping = (components.queryItems ?? []).reduce(into: [String: String](), { result, item in
                result[item.name] = item.value
            })
            let transport: MGConfiguration.Outbound.StreamSettings.Transport
            if let value = mapping["type"], !value.isEmpty {
                if let value = MGConfiguration.Outbound.StreamSettings.Transport(rawValue: value) {
                    transport = value
                } else {
                    throw NSError.newError("unknown transport")
                }
            } else {
                throw NSError.newError("Transport method cannot be empty")
            }
            let security: MGConfiguration.Outbound.StreamSettings.Security
            if let value = mapping["security"] {
                if value.isEmpty {
                    throw NSError.newError("Transport Security cannot be empty")
                } else {
                    if let value = MGConfiguration.Outbound.StreamSettings.Security(rawValue: value) {
                        security = value
                    } else {
                        throw NSError.newError("unknown transport security method")
                    }
                }
            } else {
                security = .none
            }
            self.protocolType = protocolType
            self.user = user
            self.host = host
            self.port = port
            self.transport = transport
            self.security = security
            self.queryMapping = mapping
            self.descriptive = components.fragment ?? ""
        }
    }
}


protocol MGConfigurationParserProtocol {
    
    associatedtype Output
    
    static func parse(with components: MGConfiguration.URLComponents) throws -> Output
}

extension MGConfiguration.Outbound.VLESSSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var vless = MGConfiguration.Outbound.VLESSSettings()
        vless.address = components.host
        vless.port = components.port
        vless.user.id = components.user
        if let value = components.queryMapping["encryption"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(String(localized: "encriptionEmpty"))")
            } else {
                if value == "none" {
                    vless.user.encryption = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) \(String(localized: "unsupportedEncriptionAlgorithm")): \(value)")
                }
            }
        } else {
            vless.user.encryption = "none"
        }
        if let value = components.queryMapping["flow"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(String(localized: "flowControllEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.VLESSSettings.Flow(rawValue: value) {
                    vless.user.flow = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) 不支持的流控: \(value)")
                }
            }
        } else {
            vless.user.flow = .none
        }
        return vless
    }
}

extension MGConfiguration.Outbound.VMessSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var vmess = MGConfiguration.Outbound.VMessSettings()
        vmess.address = components.host
        vmess.port = components.port
        vmess.user.id = components.user
        if let value = components.queryMapping["encryption"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) 加密算法不能为空")
            } else {
                if let value = MGConfiguration.Outbound.Encryption(rawValue: value) {
                    vmess.user.security = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) 不支持的加密算法: \(value)")
                }
            }
        } else {
            vmess.user.security = .auto
        }
        return vmess
    }
}

extension MGConfiguration.Outbound.TrojanSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        throw NSError.newError("Unsupported")
    }
}

extension MGConfiguration.Outbound.ShadowsocksSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        throw NSError.newError("Unsupported")
    }
}

extension MGConfiguration.Outbound.StreamSettings.TCPSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        return MGConfiguration.Outbound.StreamSettings.TCPSettings()
    }
}

extension MGConfiguration.Outbound.StreamSettings.KCPSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var kcp = MGConfiguration.Outbound.StreamSettings.KCPSettings()
        if let value = components.queryMapping["headerType"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) headerType \(String(localized: "canNotBeEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.StreamSettings.HeaderType(rawValue: value) {
                    kcp.header.type = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) headerType \(String(localized: "unsupportedType")): \(value)")
                }
            }
        } else {
            kcp.header.type = .none
        }
        if let value = components.queryMapping["seed"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) seed \(String(localized: "canNotBeEmpty"))")
            } else {
                kcp.seed = value
            }
        } else {
            kcp.seed = ""
        }
        return kcp
    }
}

extension MGConfiguration.Outbound.StreamSettings.WSSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var ws = MGConfiguration.Outbound.StreamSettings.WSSettings()
        if let value = components.queryMapping["host"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) host \(String(localized: "canNotBeEmpty"))")
            } else {
                ws.headers["Host"] = value
            }
        } else {
            ws.headers["Host"] = components.host
        }
        if let value = components.queryMapping["path"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) path \(String(localized: "canNotBeEmpty"))")
            } else {
                ws.path = value
            }
        } else {
            ws.path = "/"
        }
        return ws
    }
}

extension MGConfiguration.Outbound.StreamSettings.HTTPSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var http = MGConfiguration.Outbound.StreamSettings.HTTPSettings()
        if let value = components.queryMapping["host"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) host \(String(localized: "canNotBeEmpty"))")
            } else {
                http.host = [value]
            }
        } else {
            http.host = [components.host]
        }
        if let value = components.queryMapping["path"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) path \(String(localized: "canNotBeEmpty"))")
            } else {
                http.path = value
            }
        } else {
            http.path = "/"
        }
        return http
    }
}

extension MGConfiguration.Outbound.StreamSettings.QUICSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var quic = MGConfiguration.Outbound.StreamSettings.QUICSettings()
        if let value = components.queryMapping["quicSecurity"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) quicSecurity \(String(localized: "canNotBeEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.Encryption.init(rawValue: value) {
                    quic.security = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) quicSecurity \(String(localized: "unsupportedType")): \(value)")
                }
            }
        } else {
            quic.security = .none
        }
        if let value = components.queryMapping["key"] {
            if quic.security == .none {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) quicSecurity for none, key cannot appear")
            }
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) key \(String(localized: "canNotBeEmpty"))")
            } else {
                quic.key = value
            }
        } else {
            quic.key = ""
        }
        if let value = components.queryMapping["headerType"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) headerType \(String(localized: "canNotBeEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.StreamSettings.HeaderType(rawValue: value) {
                    quic.header.type = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) headerType \(String(localized: "unsupportedType")): \(value)")
                }
            }
        } else {
            quic.header.type = .none
        }
        return quic
    }
}

extension MGConfiguration.Outbound.StreamSettings.GRPCSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var grpc = MGConfiguration.Outbound.StreamSettings.GRPCSettings()
        if let value = components.queryMapping["serviceName"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) serviceName \(String(localized: "canNotBeEmpty"))")
            } else {
                grpc.serviceName = value
            }
        } else {
            grpc.serviceName = ""
        }
        if let value = components.queryMapping["mode"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) \(components.transport.rawValue) mode \(String(localized: "canNotBeEmpty"))")
            } else {
                grpc.multiMode = value == "multi"
            }
        } else {
            grpc.multiMode = false
        }
        return grpc
    }
}

extension MGConfiguration.Outbound.StreamSettings.TLSSettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var tls = MGConfiguration.Outbound.StreamSettings.TLSSettings()
        if let value = components.queryMapping["sni"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) TLS sni \(String(localized: "canNotBeEmpty"))")
            } else {
                tls.serverName = value
            }
        } else {
            tls.serverName = components.host
        }
        if let value = components.queryMapping["fp"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) TLS fp \(String(localized: "canNotBeEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.StreamSettings.Fingerprint(rawValue: value) {
                    tls.fingerprint = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) TLS \(String(localized: "fingerprintNotSupported")): \(value)")
                }
            }
        } else {
            tls.fingerprint = .chrome
        }
        if let value = components.queryMapping["alpn"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) TLS alpn \(String(localized: "fingerprintNotSupported"))")
            } else {
                tls.alpn = Set(value.components(separatedBy: ",").compactMap(MGConfiguration.Outbound.StreamSettings.ALPN.init(rawValue:)))
            }
        } else {
            tls.alpn = Set(MGConfiguration.Outbound.StreamSettings.ALPN.allCases)
        }
        return tls
    }
}

extension MGConfiguration.Outbound.StreamSettings.RealitySettings: MGConfigurationParserProtocol {
        
    static func parse(with components: MGConfiguration.URLComponents) throws -> Self {
        var reality = MGConfiguration.Outbound.StreamSettings.RealitySettings()
        if let value = components.queryMapping["pbk"], !value.isEmpty {
            reality.publicKey = value
        } else {
            throw NSError.newError("\(components.protocolType.description) Reality pbk \(String(localized: "illegal"))")
        }
        reality.shortId = components.queryMapping["sid"] ?? ""
        reality.spiderX = components.queryMapping["spx"] ?? ""
        if let value = components.queryMapping["sni"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) Reality sni \(String(localized: "canNotBeEmpty"))")
            } else {
                reality.serverName = value
            }
        } else {
            reality.serverName = components.host
        }
        if let value = components.queryMapping["fp"] {
            if value.isEmpty {
                throw NSError.newError("\(components.protocolType.description) Reality fp \(String(localized: "canNotBeEmpty"))")
            } else {
                if let value = MGConfiguration.Outbound.StreamSettings.Fingerprint(rawValue: value) {
                    reality.fingerprint = value
                } else {
                    throw NSError.newError("\(components.protocolType.description) Reality \(String(localized: "fingerprintNotSupported")): \(value)")
                }
            }
        } else {
            reality.fingerprint = .chrome
        }
        return reality
    }
}

extension MGConfiguration.Outbound {
    
    init(components: MGConfiguration.URLComponents) throws {
        self.protocolType   = components.protocolType
        switch self.protocolType {
        case .vless:
            self.vlessSettings = try MGConfiguration.Outbound.VLESSSettings.parse(with: components)
        case .vmess:
            self.vmessSettings = try MGConfiguration.Outbound.VMessSettings.parse(with: components)
        case .trojan:
            self.trojanSettings = try MGConfiguration.Outbound.TrojanSettings.parse(with: components)
        case .shadowsocks:
            self.shadowsocksSettings = try MGConfiguration.Outbound.ShadowsocksSettings.parse(with: components)
        case .dns, .freedom, .blackhole:
            fatalError()
        }
        self.streamSettings.transport = components.transport
        switch self.streamSettings.transport {
        case .tcp:
            self.streamSettings.tcpSettings = try MGConfiguration.Outbound.StreamSettings.TCPSettings.parse(with: components)
        case .kcp:
            self.streamSettings.kcpSettings = try MGConfiguration.Outbound.StreamSettings.KCPSettings.parse(with: components)
        case .ws:
            self.streamSettings.wsSettings = try MGConfiguration.Outbound.StreamSettings.WSSettings.parse(with: components)
        case .http:
            self.streamSettings.httpSettings = try MGConfiguration.Outbound.StreamSettings.HTTPSettings.parse(with: components)
        case .quic:
            self.streamSettings.quicSettings = try MGConfiguration.Outbound.StreamSettings.QUICSettings.parse(with: components)
        case .grpc:
            self.streamSettings.grpcSettings = try MGConfiguration.Outbound.StreamSettings.GRPCSettings.parse(with: components)
        }
        self.streamSettings.security = components.security
        switch self.streamSettings.security {
        case .none:
            break
        case .tls:
            self.streamSettings.tlsSettings = try MGConfiguration.Outbound.StreamSettings.TLSSettings.parse(with: components)
        case .reality:
            self.streamSettings.realitySettings = try MGConfiguration.Outbound.StreamSettings.RealitySettings.parse(with: components)
        }
    }
}
