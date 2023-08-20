import SwiftUI

struct MGNetworkSettingView: View {
    
    @EnvironmentObject private var packetTunnelManager: MGPacketTunnelManager
    @ObservedObject private var networkViewModel: MGNetworkViewModel
    
    init(networkViewModel: MGNetworkViewModel) {
        self._networkViewModel = ObservedObject(initialValue: networkViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                Toggle(String(localized: "hideVpnIcon"), isOn: $networkViewModel.hideVPNIcon)
            } header: {
                Text("VPN")
            } footer: {
                Text(String(localized: "excludeRoute") + " 0:0:0:0/8 & ::/128")
            }
            Section {
                Toggle(String(localized: "enableIPv6Routing"), isOn: $networkViewModel.ipv6Enabled)
            } header: {
                Text("Tunnel")
            } footer: {
                Text("ipv6Issue")
            }
        }
        .navigationTitle(Text("networkSettings"))
        .navigationBarTitleDisplayMode(.large)
        .onDisappear {
            self.networkViewModel.save {
                guard let status = packetTunnelManager.status, status == .connected else {
                    return
                }
                packetTunnelManager.stop()
                Task(priority: .userInitiated) {
                    do {
                        try await Task.sleep(for: .milliseconds(500))
                        try await packetTunnelManager.start()
                    } catch {
                        debugPrint(error.localizedDescription)
                    }
                }
            }
        }
    }
}
