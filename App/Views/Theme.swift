// Copied from OpenWarp (github.com/ImanMontajabi/OpenWarp, ui/macos/Theme.swift at a83dc7b): keep the two in step.
// Left out, as OpenWarp-only: ModeInfo (its connection modes), Metrics (its window) and Tint (its mode colour).
// Rat's own tokens built on these are in RatTheme.swift.

// Design tokens: palette, mode accents, spacing, radii, typography, motion.
// Dark, matte, muted pastels (Catppuccin-inspired, no purple, no glow).

import SwiftUI
import AppKit

// MARK: - Colour helpers

struct RGB: Equatable {
    var r: Double, g: Double, b: Double
    init(_ hex: UInt32) {
        r = Double((hex >> 16) & 0xFF) / 255
        g = Double((hex >> 8) & 0xFF) / 255
        b = Double(hex & 0xFF) / 255
    }
    init(r: Double, g: Double, b: Double) { self.r = r; self.g = g; self.b = b }
    var color: Color { Color(.sRGB, red: r, green: g, blue: b, opacity: 1) }
    var nsColor: NSColor { NSColor(srgbRed: r, green: g, blue: b, alpha: 1) }
    /// Linear blend toward `other` by `t` (0…1).
    func mix(_ other: RGB, _ t: Double) -> RGB {
        RGB(r: r + (other.r - r) * t, g: g + (other.g - g) * t, b: b + (other.b - b) * t)
    }
}

// MARK: - Palette

enum Palette {
    static let base = RGB(0x1B1C21)       // window background (uniform, incl. title area)
    static let surface = RGB(0x24252B)    // cards
    static let raised = RGB(0x2E2F36)     // controls, idle tiles
    static let hover = RGB(0x373840)
    static let cloudIdle = RGB(0x4B4D57)

    static let text = Color(red: 0.91, green: 0.91, blue: 0.93)
    static let textSecondary = Color(red: 0.64, green: 0.65, blue: 0.70)
    static let textTertiary = Color(red: 0.45, green: 0.46, blue: 0.51)
    static let onAccent = Color(red: 0.11, green: 0.11, blue: 0.13) // dark text on pastel fills
    static let hairline = Color.white.opacity(0.06)

    static let danger = RGB(0xE8898C)
    static let success = RGB(0xA6D99B)
    static let warning = RGB(0xEED49F)
}

// MARK: - Layout tokens

enum Space {
    static let xxs: CGFloat = 4
    static let xs: CGFloat = 8
    static let sm: CGFloat = 12
    static let md: CGFloat = 16
    static let lg: CGFloat = 20
    static let xl: CGFloat = 24
    static let xxl: CGFloat = 32
}

enum Radius {
    static let sm: CGFloat = 8
    static let md: CGFloat = 12
    static let lg: CGFloat = 16
}

// MARK: - Typography

enum Typo {
    static let pageTitle = Font.system(size: 22, weight: .semibold)
    static let sectionHeader = Font.system(size: 12, weight: .semibold)
    static let rowTitle = Font.system(size: 13, weight: .medium)
    static let rowValue = Font.system(size: 13)
    static let caption = Font.system(size: 11.5)
    static let mono = Font.system(size: 12, design: .monospaced)
    static let statusTitle = Font.system(size: 26, weight: .semibold)
    static let body = Font.system(size: 13)
    static let navLabel = Font.system(size: 10.5, weight: .medium)
}

// MARK: - Motion

enum Motion {
    static let quick = Animation.easeOut(duration: 0.18)
    static let standard = Animation.easeInOut(duration: 0.25)
    static let accent = Animation.easeInOut(duration: 0.35)
    static let spring = Animation.spring(response: 0.3, dampingFraction: 0.85)
    /// Forces the Reduce Motion behaviour (set for UI-test launches so continuous
    /// animations cannot make tests flaky).
    nonisolated(unsafe) static var forceReduced = false
}

extension EnvironmentValues {
    /// The system Reduce Motion setting, or `Motion.forceReduced`. Read this
    /// instead of `accessibilityReduceMotion`.
    var owReduceMotion: Bool { accessibilityReduceMotion || Motion.forceReduced }
}

extension View {
    /// Applies `animation` unless Reduce Motion is on.
    func motion<V: Equatable>(_ animation: Animation, value: V) -> some View {
        modifier(MotionModifier(animation: animation, value: value))
    }
}

private struct MotionModifier<V: Equatable>: ViewModifier {
    @Environment(\.owReduceMotion) private var reduce
    var animation: Animation
    var value: V
    func body(content: Content) -> some View {
        content.animation(reduce ? .linear(duration: 0.12) : animation, value: value)
    }
}
