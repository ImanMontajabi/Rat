// The keyboard input source, for scripts/test-ui.sh: XCUITest types characters through the current layout, so a
// non-Latin one (Persian, Russian, …) turns "london" into other letters or shortcuts.
//
//   swift scripts/input-source.swift get            prints the current input source's ID
//   swift scripts/input-source.swift latin          selects an enabled U.S. or ABC layout, prints the previous ID
//   swift scripts/input-source.swift select <id>    selects an enabled input source
import Carbon
import Foundation

func id(_ s: TISInputSource) -> String {
    Unmanaged<CFString>.fromOpaque(TISGetInputSourceProperty(s, kTISPropertyInputSourceID)).takeUnretainedValue() as String
}

func enabled(_ wanted: String) -> TISInputSource? {
    let filter = [kTISPropertyInputSourceID as String: wanted] as CFDictionary
    let list = TISCreateInputSourceList(filter, false)?.takeRetainedValue() as? [TISInputSource]
    return list?.first
}

let args = CommandLine.arguments.dropFirst()
let current = id(TISCopyCurrentKeyboardInputSource().takeRetainedValue())
switch args.first {
case "get":
    print(current)
case "latin":
    print(current)
    let latin = ["com.apple.keylayout.US", "com.apple.keylayout.ABC"]
    guard !latin.contains(current) else { exit(0) }
    guard let s = latin.lazy.compactMap(enabled).first, TISSelectInputSource(s) == noErr else {
        FileHandle.standardError.write(Data("no U.S. or ABC keyboard layout is enabled (System Settings > Keyboard > Input Sources)\n".utf8))
        exit(1)
    }
case "select":
    guard let wanted = args.dropFirst().first, let s = enabled(wanted), TISSelectInputSource(s) == noErr else {
        FileHandle.standardError.write(Data("cannot select \(args.dropFirst().first ?? "nothing")\n".utf8))
        exit(1)
    }
default:
    FileHandle.standardError.write(Data("usage: input-source.swift get | latin | select <id>\n".utf8))
    exit(2)
}
