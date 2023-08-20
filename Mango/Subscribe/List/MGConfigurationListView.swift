import SwiftUI
import CodeScanner

final class MGConfigurationListViewModel: ObservableObject {
    @Published var location: MGConfigurationLocation?
    @Published var protocolType: MGConfiguration.Outbound.ProtocolType?
}

extension MGConfiguration {
    
    var typeString: String {
        if let pt = self.attributes.source.scheme.flatMap(MGConfiguration.Outbound.ProtocolType.init(rawValue:)) {
            return pt.description
        } else {
            if self.attributes.source.isFileURL {
                return String(localized: "local")
            } else {
                return String(localized: "remote")
            }
        }
    }
}

fileprivate extension MGConfiguration {
    
    var isUserCreated: Bool {
        self.attributes.source.scheme.flatMap(MGConfiguration.Outbound.ProtocolType.init(rawValue:)) != nil
    }
    
    var isLocal: Bool {
        self.attributes.source.isFileURL || self.isUserCreated
    }
}

private struct MGConfigurationEditModel: Identifiable {
    
    let id: UUID
    let name: String
    let model: MGConfiguration.Outbound
    
    init(configuration: MGConfiguration) throws {
        guard let id = UUID(uuidString: configuration.id) else {
            throw NSError.newError("Invalid configuration")
        }
        self.id = id
        self.name = configuration.attributes.alias
        let fileURL = MGConstant.configDirectory.appending(component: "\(configuration.id)/config.json")
        let data = try Data(contentsOf: fileURL)
        self.model = try JSONDecoder().decode(MGConfiguration.Outbound.self, from: data)
    }
    
    init(urlString: String) throws {
        let components = try MGConfiguration.URLComponents(urlString: urlString)
        self.id = UUID()
        self.name = components.descriptive
        self.model = try MGConfiguration.Outbound(components: components)
    }
}

struct MGConfigurationListView: View {
    
    @Environment(\.dismiss) private var dismiss
    
    @EnvironmentObject private var packetTunnelManager: MGPacketTunnelManager
    @EnvironmentObject private var configurationListManager: MGConfigurationListManager
        
    @State private var isRenameAlertPresented = false
    @State private var configurationName: String = ""
    
    @State private var editModel: MGConfigurationEditModel?
        
    @State private var isConfirmationDialogPresented = false
    
    @State private var isCodeScannerPresented: Bool = false
    @State private var scanResult: Swift.Result<ScanResult, ScanError>?
    
    let current: Binding<String>
    @ObservedObject var configurationListViewModel: MGConfigurationListViewModel
    
    init(current: Binding<String>, configurationListViewModel: MGConfigurationListViewModel) {
        self.current = current
        self._configurationListViewModel = ObservedObject(initialValue: configurationListViewModel)
    }
    
    var body: some View {
        ForEach(configurationListManager.configurations) { configuration in
            ConfigurationItemView(configuration: configuration)
                .listRowBackground(current.wrappedValue == configuration.id ? Color.accentColor : nil)
        }
        .sheet(item: $configurationListViewModel.location) { location in
            MGConfigurationLoadView(location: location)
        }
        .fullScreenCover(item: $editModel, onDismiss: { configurationListManager.reload() }) { em in
            MGConfigurationEditView(
                vm: MGConfigurationEditViewModel(id: em.id, name: em.name, model: em.model)
            )
        }
        .fullScreenCover(isPresented: $isCodeScannerPresented) {
            guard let res = self.scanResult else {
                return
            }
            self.scanResult = nil
            self.handleScanResult(res)
        } content: {
            EmptyView()
//            MGQRCodeScannerView(result: $scanResult)
        }
    }
    
    private func handleScanResult(_ result: Swift.Result<ScanResult, ScanError>) {
        switch result {
        case .success(let success):
            do {
                self.editModel = try MGConfigurationEditModel(urlString: success.string)
            } catch {
                MGNotification.send(title: "", subtitle: "", body: error.localizedDescription)
            }
        case .failure(let failure):
            let message: String
            switch failure {
            case .badInput:
                message = String(localized: "inputError")
            case .badOutput:
                message = String(localized: "outputError")
            case .permissionDenied:
                message = String(localized: "permissionError")
            case .initError(let error):
                message = error.localizedDescription
            }
            MGNotification.send(title: "", subtitle: "", body: message)
        }
    }
    
    @ViewBuilder
    private func ConfigurationItemView(configuration: MGConfiguration) -> some View {
        Button {
            guard current.wrappedValue != configuration.id else {
                return
            }
            current.wrappedValue = configuration.id
        } label: {
            HStack(alignment: .center, spacing: 4) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(configuration.attributes.alias)
                        .foregroundColor(current.wrappedValue == configuration.id ? .white : .primary)
                        .fontWeight(.medium)
                    Text(configuration.typeString)
                        .foregroundColor(current.wrappedValue == configuration.id ? .white : .primary)
                        .font(.caption)
                        .fontWeight(.light)
                }
                Spacer()
                if configurationListManager.downloadingConfigurationIDs.contains(configuration.id) {
                    ProgressView()
                } else {
                    TimelineView(.periodic(from: Date(), by: 1)) { _ in
                        Text(configuration.attributes.leastUpdated.formatted(.relative(presentation: .numeric)))
                            .foregroundColor(current.wrappedValue == configuration.id ? .white : .primary)
                            .font(.callout)
                            .fontWeight(.light)
                    }
                }
            }
            .lineLimit(1)
        }
        .contextMenu {
            RenameOrEditButton(configuration: configuration)
            UpdateButton(configuration: configuration)
            Divider()
            DeleteButton(configuration: configuration)
        }
    }
    
    @ViewBuilder
    private func NoConfigurationView() -> some View {
        HStack {
            Spacer()
            VStack(spacing: 20) {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.largeTitle)
                Text("NoConfigurationYet")
            }
            .foregroundColor(.secondary)
            .padding()
            Spacer()
        }
    }
    
    @ViewBuilder
    private func RenameOrEditButton(configuration: MGConfiguration) -> some View {
        Button {
            if configuration.isUserCreated {
                do {
                    self.editModel = try MGConfigurationEditModel(configuration: configuration)
                } catch {
                    MGNotification.send(title: "", subtitle: "", body: "\(String(localized: "failedToLoadFile")) \(error.localizedDescription)")
                }
            } else {
                self.configurationName = configuration.attributes.alias
                self.isRenameAlertPresented.toggle()
            }
        } label: {
            Label(configuration.isUserCreated ? String(localized: "edit") : String(localized: "rename"), systemImage: "square.and.pencil")
        }
        .alert(String(localized: "rename"), isPresented: $isRenameAlertPresented) {
            TextField(String(localized: "enterConfigName"), text: $configurationName)
            Button(String(localized: "sure")) {
                let name = configurationName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !(name == configuration.attributes.alias || name.isEmpty) else {
                    return
                }
                do {
                    try configurationListManager.rename(configuration: configuration, name: name)
                } catch {
                    MGNotification.send(title: "", subtitle: "", body: "\(String(localized: "renameFailedReason")) \(error.localizedDescription)")
                }
            }
            Button(String(localized: "cancel"), role: .cancel) {}
        }
    }
    
    @ViewBuilder
    private func UpdateButton(configuration: MGConfiguration) -> some View {
        Button {
            Task(priority: .userInitiated) {
                do {
                    try await configurationListManager.update(configuration: configuration)
                    MGNotification.send(title: "", subtitle: "", body: "\"\(configuration.attributes.alias)\"\(String(localized: "updateCompleted"))")
                    if configuration.id == current.wrappedValue {
                        guard let status = packetTunnelManager.status, status == .connected else {
                            return
                        }
                        packetTunnelManager.stop()
                        do {
                            try await packetTunnelManager.start()
                        } catch {
                            debugPrint(error.localizedDescription)
                        }
                    }
                } catch {
                    MGNotification.send(title: "", subtitle: "", body: "\"\(configuration.attributes.alias)\"\(String(localized: "updateFailedReason")) \(error.localizedDescription)")
                }
            }
        } label: {
            Label(String(localized: "renew"), systemImage: "arrow.triangle.2.circlepath")
        }
        .disabled(configurationListManager.downloadingConfigurationIDs.contains(configuration.id) || configuration.isLocal)
    }
    
    @ViewBuilder
    private func DeleteButton(configuration: MGConfiguration) -> some View {
        Button(role: .destructive) {
            do {
                try configurationListManager.delete(configuration: configuration)
                MGNotification.send(title: "", subtitle: "", body: "\"\(configuration.attributes.alias)\"\(String(localized: "successfullyDeleted"))")
                if configuration.id == current.wrappedValue {
                    current.wrappedValue = ""
                    packetTunnelManager.stop()
                }
            } catch {
                MGNotification.send(title: "", subtitle: "", body: "\"\(configuration.attributes.alias)\"\(String(localized: "deleteFailedReason")) \(error.localizedDescription)")
            }
        } label: {
            Label(String(localized: "delete"), systemImage: "trash")
        }
        .disabled(configurationListManager.downloadingConfigurationIDs.contains(configuration.id))
    }
}
