import Foundation

@main
struct AppOrganizationTests {
    static func main() {
        var organization = LCAppOrganization()
        precondition(organization.createFolder(named: " \n ", isHidden: false) == nil)
        let games = organization.createFolder(named: " Games ", isHidden: false)!
        let tools = organization.createFolder(named: "Tools", isHidden: false)!
        let hidden = organization.createFolder(named: "Private", isHidden: true)!
        precondition(organization.folders[0].name == "Games")

        // Two installations with the same bundle ID stay independently organized.
        let first = "com.example.game:first.app"
        let second = "com.example.game:second.app"
        organization.moveApp(first, to: games, isHidden: false)
        organization.moveApp(second, to: tools, isHidden: false)
        precondition(organization.folderID(for: first, isHidden: false) == games)
        precondition(organization.folderID(for: second, isHidden: false) == tools)

        // A folder in the other visibility group is neither exposed nor assignable.
        precondition(organization.folderID(for: first, isHidden: true) == nil)
        organization.moveApp(first, to: hidden, isHidden: false)
        precondition(organization.folderID(for: first, isHidden: false) == games)
        organization.moveApp("secret", to: hidden, isHidden: true)
        precondition(organization.folderID(for: "secret", isHidden: true) == hidden)
        precondition(organization.folderID(for: "secret", isHidden: false) == nil)

        organization.toggleFavorite(first)
        organization.toggleFavorite("unfiledFavorite")
        organization.moveApp("plain", to: games, isHidden: false)
        organization.moveApp("other", to: games, isHidden: false)
        let sorted = ["plain", "unfiledFavorite", second, first, "other"]
        precondition(organization.favoritesFirst(sorted) { $0 } == ["unfiledFavorite", first, "plain", second, "other"])
        let folderApps = sorted.filter { organization.folderID(for: $0, isHidden: false) == games }
        precondition(organization.favoritesFirst(folderApps) { $0 } == [first, "plain", "other"])
        organization.toggleFavorite("unfiledFavorite")
        precondition(!organization.favoriteApps.contains("unfiledFavorite"))
        let missingID: [String?] = [nil, first, second]
        precondition(organization.favoritesFirst(missingID) { $0 } == [first, nil, second])

        organization.renameFolder(games, to: " Arcade ")
        organization.renameFolder(games, to: "   ")
        precondition(organization.folders[0].name == "Arcade")
        organization.folders[0].isExpanded = false

        let suite = "LCAppOrganizationTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        organization.save(to: defaults)
        var restored = LCAppOrganization.load(from: defaults)
        precondition(restored.folders == organization.folders)
        precondition(restored.appFolders == organization.appFolders)
        precondition(restored.favoriteApps == organization.favoriteApps)

        restored.deleteFolder(games)
        precondition(restored.folderID(for: first, isHidden: false) == nil)
        precondition(restored.favoriteApps.contains(first))
        precondition(restored.folderID(for: second, isHidden: false) == tools)
        restored.moveApp(second, to: nil, isHidden: false)
        precondition(restored.folderID(for: second, isHidden: false) == nil)
        restored.moveApp(second, to: UUID(), isHidden: false)
        precondition(restored.folderID(for: second, isHidden: false) == nil)
        restored.removeApp(first)
        precondition(!restored.favoriteApps.contains(first))
        restored.removeApp("secret")
        precondition(restored.appFolders["secret"] == nil)

        defaults.set(Data("invalid".utf8), forKey: LCAppOrganization.defaultsKey)
        precondition(LCAppOrganization.load(from: defaults).folders.isEmpty)
        print("Guest app organization tests passed")
    }
}
