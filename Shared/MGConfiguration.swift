import Foundation

public struct MGConfiguration: Identifiable {
    
    public struct Attributes: Codable {
        
        public static let key = "Configuration.Attributes"
        
        public let alias: String
        public let source: URL
        public let leastUpdated: Date
    }
    
    public static let currentStoreKey = "XRAY_CURRENT"
    
    public static let key = FileAttributeKey("NSFileExtendedAttributes")
    
    public let id: String
    public let creationDate: Date
    public let attributes: Attributes
    
    init(uuidString: String) throws {
        guard let uuid = UUID(uuidString: uuidString) else {
            throw NSError.newError("config file does not exist")
        }
        let folderURL = MGConstant.configDirectory.appending(component: "\(uuid.uuidString)", directoryHint: .isDirectory)
        guard FileManager.default.fileExists(atPath: folderURL.path(percentEncoded: false)) else {
            throw NSError.newError("config file does not exist")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: folderURL.path(percentEncoded: false))
        guard let creationDate = attributes[.creationDate] as? Date,
              let extends = attributes[MGConfiguration.key] as? [String: Data],
              let data = extends[MGConfiguration.Attributes.key] else {
            throw NSError.newError("Configuration file parsing failed")
        }
        self.id = uuid.uuidString
        self.creationDate = creationDate
        self.attributes = try JSONDecoder().decode(MGConfiguration.Attributes.self, from: data)
    }
}
