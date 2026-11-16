import SwiftUI
import AppKit

/// Rat's flags: a flat rectangle with rounded corners, a bold dark outline, a slightly darker right and bottom
/// edge and a faint sheen, like an app-quality icon flag rather than an emoji. The artwork is flag-icons' flat
/// 4:3 SVGs (MIT, bundled in `Flags/`, drawn by AppKit's own SVG support), framed here, so all flags share one
/// size, one outline and one shape. A region without a file has no flag.
@MainActor
enum Flags {
    /// Width over height, like the reference flags.
    nonisolated static let aspect: CGFloat = 1.45
    private static var artwork: [String: NSImage] = [:]
    private static var missing = Set<String>()
    private static var images: [String: NSImage] = [:]

    /// The flag of a region code, `height` points high, or nil for a code with no flag (unknown, `ZZ`).
    static func image(_ code: String, height: CGFloat) -> NSImage? {
        let key = "\(code.uppercased())|\(height)"
        if let i = images[key] { return i }
        guard let art = art(code) else { return nil }
        let size = NSSize(width: (height * aspect).rounded(), height: height)
        let image = NSImage(size: size, flipped: false) { rect in
            draw(art, in: rect)
            return true
        }
        image.accessibilityDescription = Countries.name(code.uppercased())
        if images.count > 600 { images.removeAll() }
        images[key] = image
        return image
    }

    /// The flag's artwork (`Flags/<code>.svg` in the app's resources), loaded once per region.
    static func art(_ code: String) -> NSImage? {
        let c = code.lowercased()
        if let a = artwork[c] { return a }
        guard !missing.contains(c) else { return nil }
        guard c.count == 2, c.allSatisfy({ $0.isASCII && $0.isLetter }),
              let url = Bundle.main.url(forResource: c, withExtension: "svg", subdirectory: "Flags"),
              let a = NSImage(contentsOf: url), a.size.width > 0, a.size.height > 0 else { missing.insert(c); return nil }
        artwork[c] = a
        return a
    }

    /// The framed flag in `rect`: artwork filling a rounded rectangle, the darker right and bottom edges, a sheen
    /// on the top half, and the outline last so it sits over everything.
    static func draw(_ art: NSImage, in rect: CGRect) {
        guard let ctx = NSGraphicsContext.current?.cgContext else { return }
        let line = max(1, rect.height * 0.085)
        let outer = rect.insetBy(dx: line / 2, dy: line / 2)
        let radius = rect.height * 0.2
        let shape = CGPath(roundedRect: outer, cornerWidth: radius, cornerHeight: radius, transform: nil)
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        // Fill the frame, cropping the longer side (the 4:3 artwork loses a little top and bottom).
        let artAspect = art.size.width / art.size.height, frameAspect = outer.width / outer.height
        var target = outer
        if artAspect > frameAspect { target.size.width = outer.height * artAspect; target.origin.x -= (target.width - outer.width) / 2 }
        else { target.size.height = outer.width / artAspect; target.origin.y -= (target.height - outer.height) / 2 }
        art.draw(in: target, from: .zero, operation: .sourceOver, fraction: 1)
        // Bevel: the right and bottom edges a shade darker (the reference flags' depth), the top a faint sheen.
        let band = outer.height * 0.13
        ctx.setFillColor(NSColor.black.withAlphaComponent(0.16).cgColor)
        ctx.fill(CGRect(x: outer.maxX - band * 0.8, y: outer.minY, width: band * 0.8, height: outer.height))
        ctx.fill(CGRect(x: outer.minX, y: outer.minY, width: outer.width - band * 0.8, height: band))
        let sheen = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                               colors: [NSColor.white.withAlphaComponent(0.16).cgColor, NSColor.white.withAlphaComponent(0).cgColor] as CFArray,
                               locations: [0, 1])!
        ctx.drawLinearGradient(sheen, start: CGPoint(x: outer.minX, y: outer.maxY), end: CGPoint(x: outer.minX, y: outer.midY), options: [])
        ctx.restoreGState()
        ctx.addPath(shape)
        ctx.setStrokeColor(NSColor(srgbRed: 0.04, green: 0.04, blue: 0.05, alpha: 1).cgColor)
        ctx.setLineWidth(line)
        ctx.strokePath()
    }
}

/// A region's flag in Rat's style, `height` points high (nothing for a code with no flag). An image named for its
/// country, `flag-<CC>` for UI tests.
struct FlagView: View {
    let code: String?
    var height: CGFloat = 12

    var body: some View {
        if let c = code, let image = Flags.image(c, height: height) {
            Image(nsImage: image)
                .resizable()
                .frame(width: (height * Flags.aspect).rounded(), height: height)
                .accessibilityLabel("Flag of \(Countries.name(c.uppercased()))")
                .accessibilityIdentifier("flag-\(c.uppercased())")
        }
    }
}
