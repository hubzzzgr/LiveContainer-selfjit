import Foundation

struct LCAppFolder: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    let isHidden: Bool
    var isExpanded = true
}

/// Display organization only; deleting a folder never deletes an installed app.
struct LCAppOrganization: Codable {
    var folders: [LCAppFolder] = []
    private(set) var appFolders: [String: UUID] = [:]
    private(set) var favoriteApps: Set<String> = []

    static let defaultsKey = "LCAppOrganization"

    static func load(from defaults: UserDefaults) -> Self {
        guard let data = defaults.data(forKey: defaultsKey),
              let organization = try? JSONDecoder().decode(Self.self, from: data) else {
            return Self()
        }
        return organization
    }

    func save(to defaults: UserDefaults) {
        guard let data = try? JSONEncoder().encode(self) else { return }
        defaults.set(data, forKey: Self.defaultsKey)
    }

    @discardableResult
    mutating func createFolder(named name: String, isHidden: Bool) -> UUID? {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return nil }
        let folder = LCAppFolder(id: UUID(), name: name, isHidden: isHidden)
        folders.append(folder)
        return folder.id
    }

    mutating func renameFolder(_ id: UUID, to name: String) {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, let index = folders.firstIndex(where: { $0.id == id }) else { return }
        folders[index].name = name
    }

    mutating func deleteFolder(_ id: UUID) {
        folders.removeAll { $0.id == id }
        appFolders = appFolders.filter { $0.value != id }
    }

    func folderID(for appID: String, isHidden: Bool) -> UUID? {
        guard let id = appFolders[appID],
              folders.contains(where: { $0.id == id && $0.isHidden == isHidden }) else { return nil }
        return id
    }

    mutating func moveApp(_ appID: String, to folderID: UUID?, isHidden: Bool) {
        if let folderID {
            guard folders.contains(where: { $0.id == folderID && $0.isHidden == isHidden }) else { return }
        }
        appFolders[appID] = folderID
    }

    mutating func toggleFavorite(_ appID: String) {
        if favoriteApps.contains(appID) {
            favoriteApps.remove(appID)
        } else {
            favoriteApps.insert(appID)
        }
    }

    /// Preserve the selected sort order inside each group.
    func favoritesFirst<T>(_ apps: [T], identifier: (T) -> String?) -> [T] {
        func isFavorite(_ app: T) -> Bool {
            identifier(app).map { favoriteApps.contains($0) } ?? false
        }
        return apps.filter { isFavorite($0) } + apps.filter { !isFavorite($0) }
    }

    mutating func removeApp(_ appID: String) {
        appFolders.removeValue(forKey: appID)
        favoriteApps.remove(appID)
    }
}
