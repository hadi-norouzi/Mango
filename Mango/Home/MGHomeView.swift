import SwiftUI

struct MGHomeView: View {
    
    @Environment(\.colorScheme) private var colorScheme
    @EnvironmentObject private var packetTunnelManager: MGPacketTunnelManager
    @EnvironmentObject private var configurationListManager: MGConfigurationListManager
    
    @StateObject private var configurationListViewModel = MGConfigurationListViewModel()
    
    let current: Binding<String>
    
    @State var state : MGSwitchButton.State = .off
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    if packetTunnelManager.isProcessing {
                        ProgressView()
                    } else {
                        MGControlView()
                    }
                }
                Section {
                    ForEach(configurationListManager.configurations) { configuration in
                        MGConfigurationItemView(current: current, configuration: configuration)
                    }
                }
            }
            .navigationTitle(Text("appName"))
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                configurationListManager.reload()
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    NavigationLink {
                        MGSettingsView()
                    } label: {
                        Image(systemName: "gearshape")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        ForEach(MGConfiguration.Outbound.ProtocolType.allCases) { pt in
                            NavigationLink {
                                MGConfigurationEditView(vm: MGConfigurationEditViewModel(id: UUID(), protocolType: pt))
                            } label: {
                                Label(pt.description, systemImage: "plus")
                            }
                        }
                        Divider()
                        NavigationLink {
                            MGQRCodeScannerView { result in
                                switch result {
                                case .success(let success):
                                    print(success.string)
                                case .failure(let failure):
                                    print(failure.localizedDescription)
                                }
                                return true
                            }
                        } label: {
                            Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                        }
                        Divider()
                        NavigationLink {
                            MGConfigurationLoadView(location: .remote)
                        } label: {
                            Label("Download from URL", systemImage: "square.and.arrow.down.on.square")
                        }
                        NavigationLink {
                            MGConfigurationLoadView(location: .local)
                        } label: {
                            Label("Import from Files", systemImage: "tray.and.arrow.down")
                        }

                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
        }
    }
}

struct MGConfigurationItemView: View {
    
    @Binding var current: String
    let configuration: MGConfiguration
    
    var body: some View {
        Button {
            current = configuration.id
        } label: {
            HStack(spacing: 16) {
                Image(systemName: "circle.fill")
                    .font(.caption2)
                    .foregroundColor(Color(uiColor: current == configuration.id ? .systemGreen : .systemGray6))
                Text(configuration.attributes.alias)
                    .foregroundColor(.primary)
            }
        }
        .animation(.easeInOut, value: current)
    }
}
