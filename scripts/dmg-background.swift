// Draws the DMG window background: assets/dmg-background.tiff (640×400 points, 1x and 2x). Rerun after changing
// the layout in scripts/make-dmg.sh (icons at x 160 and 480, y 170):
//   swift scripts/dmg-background.swift assets && tiffutil -cathidpicheck assets/dmg-background.png assets/dmg-background@2x.png -out assets/dmg-background.tiff
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
let size = NSSize(width: 640, height: 400)

func draw(scale: CGFloat) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = size
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let bounds = NSRect(origin: .zero, size: size)
    // Light, so Finder's black icon labels stay readable in both appearances.
    NSGradient(starting: NSColor(calibratedRed: 0.97, green: 0.97, blue: 0.98, alpha: 1),
               ending: NSColor(calibratedRed: 0.87, green: 0.88, blue: 0.91, alpha: 1))!.draw(in: bounds, angle: -90)

    // Arrow between the two icons (AppKit's y axis points up: icon centres are at y = 400 - 170).
    let y: CGFloat = size.height - 170
    let arrow = NSBezierPath()
    arrow.move(to: NSPoint(x: 250, y: y)); arrow.line(to: NSPoint(x: 382, y: y))
    arrow.lineWidth = 5; arrow.lineCapStyle = .round
    NSColor(white: 0, alpha: 0.3).setStroke(); arrow.stroke()
    let head = NSBezierPath()
    head.move(to: NSPoint(x: 366, y: y + 16)); head.line(to: NSPoint(x: 392, y: y)); head.line(to: NSPoint(x: 366, y: y - 16))
    head.lineWidth = 5; head.lineCapStyle = .round; head.lineJoinStyle = .round
    head.stroke()

    let style = NSMutableParagraphStyle(); style.alignment = .center
    let title = NSAttributedString(string: "Drag Rat to Applications", attributes: [
        .font: NSFont.systemFont(ofSize: 17, weight: .semibold), .foregroundColor: NSColor(white: 0.1, alpha: 1), .paragraphStyle: style])
    title.draw(in: NSRect(x: 0, y: 100, width: size.width, height: 24))
    let note = NSAttributedString(string: "Ad-hoc signed · first launch: right-click Rat › Open", attributes: [
        .font: NSFont.systemFont(ofSize: 12), .foregroundColor: NSColor(white: 0.35, alpha: 1), .paragraphStyle: style])
    note.draw(in: NSRect(x: 0, y: 76, width: size.width, height: 18))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

try draw(scale: 1).write(to: URL(fileURLWithPath: "\(out)/dmg-background.png"))
try draw(scale: 2).write(to: URL(fileURLWithPath: "\(out)/dmg-background@2x.png"))
