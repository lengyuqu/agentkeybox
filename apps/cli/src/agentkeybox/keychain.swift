import Foundation
import IOKit
import Security

// Use the same physical-console state as AKB's existing macOS screen check.
// The helper enforces it too, since its read response carries a session key.
func checkConsole() {
    let root = IORegistryGetRootEntry(kIOMainPortDefault)
    guard root != 0 else { exit(5) }
    defer { IOObjectRelease(root) }
    guard let sessions = IORegistryEntryCreateCFProperty(
        root, "IOConsoleUsers" as CFString, kCFAllocatorDefault, 0
    )?.takeRetainedValue() as? [[String: Any]] else { exit(5) }
    let active = sessions.filter { $0["kCGSSessionOnConsoleKey"] as? Bool == true }
    if active.isEmpty { exit(4) }
    guard active.count == 1, let session = active.first else { exit(5) }
    guard session["kCGSSessionUserIDKey"] as? UInt32 == getuid(),
          session["kCGSessionLoginDoneKey"] as? Bool == true else { exit(4) }
    if let locked = session["CGSSessionScreenIsLocked"] {
        guard let value = locked as? Bool else { exit(5) }
        if value { exit(4) }
    }
}

let args = CommandLine.arguments
guard args.count == 3, args[2].utf8.count == 64,
      args[2].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
else { exit(64) }

checkConsole()
// The file-based login keychain supports an executable's ACL, including local builds.
// Access must fail rather than bringing up authentication UI for an agent command.
guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { exit(70) }
var keychain: SecKeychain?
guard SecKeychainCopyDefault(&keychain) == errSecSuccess, let keychain else { exit(70) }

let identity: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "dev.agentkeybox.session.v1",
    kSecAttrAccount as String: args[2],
]
var query = identity
query[kSecMatchSearchList as String] = [keychain]

switch args[1] {
case "read":
    var result: CFTypeRef?
    query[kSecReturnData as String] = true
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { exit(44) }
    guard status == errSecSuccess, let data = result as? Data else { exit(70) }
    checkConsole()
    FileHandle.standardOutput.write(data)
case "save":
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count == 88, let decoded = Data(base64Encoded: data), decoded.count == 64
    else { exit(64) }
    checkConsole()
    let value = [kSecValueData as String: data]
    var item = identity
    item[kSecUseKeychain as String] = keychain
    item[kSecValueData as String] = data
    let status = SecItemAdd(item as CFDictionary, nil)
    if status == errSecDuplicateItem {
        guard SecItemUpdate(query as CFDictionary, value as CFDictionary) == errSecSuccess
        else { exit(70) }
    } else if status != errSecSuccess {
        exit(70)
    }
case "remove":
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { exit(70) }
default:
    exit(64)
}
