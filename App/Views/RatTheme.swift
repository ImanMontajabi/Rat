import SwiftUI
import AppKit

/// Rat's colours, on OpenWarp's tokens (Theme.swift): dark, matte, muted pastels, no purple, no glow, no glass.
/// Traffic is peach going out and blue coming in, everywhere (pills, sparklines, the chart, the map's tracers).
enum RatColors {
    static let sent = RGB(0xF4AD86)       // peach: OpenWarp's Traffic and DNS accent
    static let received = RGB(0x8DB2EE)   // blue: OpenWarp's DNS-only accent
    /// Selection, the chosen place on the map, an undecided ✗/✓, unapproved rules.
    static let accent = received
    static let vpn = RGB(0x8FD3C6)        // teal
    static let proxy = RGB(0xEDD39C)      // yellow
}

extension ShapeStyle where Self == Color {
    static var ratBase: Color { Palette.base.color }
    static var ratSurface: Color { Palette.surface.color }
    static var ratRaised: Color { Palette.raised.color }
    static var ratHover: Color { Palette.hover.color }
    static var ratHairline: Color { Palette.hairline }
    static var ratSent: Color { RatColors.sent.color }
    static var ratReceived: Color { RatColors.received.color }
    static var ratAccent: Color { RatColors.accent.color }
    static var ratDanger: Color { Palette.danger.color }
    static var ratSuccess: Color { Palette.success.color }
    static var ratWarning: Color { Palette.warning.color }
    static var ratVPN: Color { RatColors.vpn.color }
    static var ratProxy: Color { RatColors.proxy.color }
    /// Dark text on a pastel fill.
    static var ratOnAccent: Color { Palette.onAccent }
}

extension NSColor {
    static var ratBase: NSColor { Palette.base.nsColor }
    static var ratSent: NSColor { RatColors.sent.nsColor }
    static var ratReceived: NSColor { RatColors.received.nsColor }
}

/// A flat button in OpenWarp's style: a filled rounded rectangle that looks the same whether or not its window is
/// key (AppKit greys a prominent button out in a window in the background, and dark text on that grey is unreadable).
struct MatteButtonStyle: ButtonStyle {
    var fill: Color
    var text: Color
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.medium))
            .foregroundStyle(text)
            .padding(.vertical, 8).padding(.horizontal, Space.sm)
            .background(fill.opacity(configuration.isPressed ? 0.8 : 1), in: RoundedRectangle(cornerRadius: Radius.sm))
            .contentShape(RoundedRectangle(cornerRadius: Radius.sm))
    }
}
