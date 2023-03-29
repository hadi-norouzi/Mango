import Foundation

extension MGConfiguration {
    
    public struct Outbound: Codable, Equatable, MGConfigurationPersistentModel {
        
        public enum Tag: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case direct, proxy, block, dns
            public var description: String {
                switch self {
                case .direct:
                    return "Direct"
                case .proxy:
                    return "Proxy"
                case .block:
                    return "Block"
                case .dns:
                    return "DNS"
                }
            }
        }
        
        public struct DNSSettings: Codable, Equatable {
            public enum Network: String, Codable, Identifiable, CustomStringConvertible, CaseIterable {
                public var id: Self { self }
                case tcp, udp, none
                public var description: String {
                    switch self {
                    case .tcp:
                        return "TCP"
                    case .udp:
                        return "UDP"
                    case .none:
                        return "None"
                    }
                }
                
                public init(from decoder: Decoder) throws {
                    let coantiner = try decoder.singleValueContainer()
                    self = Network(rawValue: try coantiner.decode(String.self)) ?? .none
                }
                
                public func encode(to encoder: Encoder) throws {
                    if self == .none {
                        return
                    } else {
                        var container = encoder.singleValueContainer()
                        try container.encode(self.rawValue)
                    }
                }
            }
            public var network: Network = .none
            public var address: String?
            public var port: Int?
        }
        
        public struct FreedomSettings: Codable, Equatable {
            public enum DomainStrategy: String, Codable, Identifiable, CaseIterable, CustomStringConvertible {
                public var id: Self { self }
                case asIs       = "AsIs"
                case useIP      = "UseIP"
                case useIPv4    = "UseIPv4"
                case useIPv6    = "UseIPv6"
                public var description: String {
                    self.rawValue
                }
            }
            public var domainStrategy: DomainStrategy = .asIs
            public var redirect: String?
            public var userLevel: Int = 0
        }
        
        public struct BlackholeSettings: Codable, Equatable {
            public enum ResponseType: String, Codable, Identifiable, CaseIterable, CustomStringConvertible {
                public var id: Self { self }
                case none, http
                public var description: String {
                    switch self {
                    case .none:
                        return "None"
                    case .http:
                        return "HTTP"
                    }
                }
            }
            public struct Response: Codable, Equatable {
                public var type: ResponseType = .none
            }
            public var response = Response()
        }
        
        public struct __Outbound__<Settings: Codable & Equatable>: Codable, Equatable {
            private var `protocol`: String
            public var settings: Settings
            private var tag: Tag
            fileprivate init(`protocol`: String, settings: Settings, tag: Tag) {
                self.protocol = `protocol`
                self.settings = settings
                self.tag = tag
            }
        }
        
        public typealias DNS        = __Outbound__<DNSSettings>
        public typealias Freedom    = __Outbound__<FreedomSettings>
        public typealias Blackhole  = __Outbound__<BlackholeSettings>
        
        public var dns          = DNS(protocol: "dns", settings: DNSSettings(), tag: .dns)
        public var freedom      = Freedom(protocol: "freedom", settings: FreedomSettings(), tag: .direct)
        public var blackhole    = Blackhole(protocol: "blackhole", settings: BlackholeSettings(), tag: .block)
        public var order        = [Tag.proxy, Tag.direct, Tag.block, Tag.dns]

        public static let storeKey = "XRAY_OUTBOUND_DATA"
        
        public static let defaultValue = MGConfiguration.Outbound()
    }
}
