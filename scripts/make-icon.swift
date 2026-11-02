// Builds Rat's app icon from its artwork (assets/icon-artwork.png, 1536×1024 on a near-black background):
// the art cropped to a square, drawn into Apple's macOS icon grid (an 824 px rounded square centred in 1024, with a
// soft shadow) on the art's own background, its top and bottom edges faded so no seam shows.
//
//   swiftc -O -o "$TMPDIR/make-icon" scripts/make-icon.swift
//   "$TMPDIR/make-icon" assets/icon-artwork.png assets/icon.png 175 1160      # <source> <out> <cropX> <cropSide>
//   for s in 16 32 64 128 256 512 1024; do sips -z $s $s assets/icon.png --out App/Assets.xcassets/AppIcon.appiconset/icon_$s.png; done
//   sips -z 512 512 assets/icon.png --out docs/icon.png
import AppKit
import CoreGraphics
let a = CommandLine.arguments
let src = NSImage(contentsOfFile: a[1])!.cgImage(forProposedRect: nil, context: nil, hints: nil)!
let cropX = CGFloat(Double(a[3])!), side = CGFloat(Double(a[4])!)
let W = 1024, box = CGRect(x: 100, y: 100, width: 824, height: 824)
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: W, height: W, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.interpolationQuality = .high
// The background colour: the source's corner pixel.
let rep = NSBitmapImageRep(cgImage: src)
// The background colour: the average of the source's outer frame (it is a near-black with grain).
var r = 0.0, g = 0.0, b = 0.0, n = 0.0
for y in stride(from: 0, to: rep.pixelsHigh, by: 7) { for x in stride(from: 0, to: rep.pixelsWide, by: 7)
    where y < 60 || y >= rep.pixelsHigh - 60 || x < 60 || x >= rep.pixelsWide - 60 {
    let c = rep.colorAt(x: x, y: y)!.usingColorSpace(.sRGB)!; r += c.redComponent; g += c.greenComponent; b += c.blueComponent; n += 1 } }
let bg = NSColor(srgbRed: r / n, green: g / n, blue: b / n, alpha: 1)
// A soft drop shadow under the shape, as Apple's icons have.
let shape = CGPath(roundedRect: box, cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 28, color: CGColor(gray: 0, alpha: 0.45))
ctx.addPath(shape); ctx.setFillColor(bg.cgColor); ctx.fillPath()
ctx.restoreGState()
ctx.addPath(shape); ctx.clip()
ctx.setFillColor(bg.cgColor); ctx.fill(box)
// Square crop centred vertically on the source (it may reach past the top and bottom: the background fills it).
let h = CGFloat(src.height), cropY = (h - side) / 2
let scale = box.width / side
// Source y=0 is at the top; CG's is at the bottom. Draw the whole image transformed so the crop fills the box.
let dest = CGRect(x: box.minX - cropX * scale, y: box.minY - (h - (cropY + side)) * scale,
                  width: CGFloat(src.width) * scale, height: h * scale)
// The source's own top and bottom edges fade into the background, so no seam shows where the crop passes them.
let fade: CGFloat = 90 * scale
let layer = CGContext(data: nil, width: W, height: W, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
layer.interpolationQuality = .high
layer.draw(src, in: dest)
let maskCtx = CGContext(data: nil, width: W, height: W, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpaceCreateDeviceGray(),
                        bitmapInfo: CGImageAlphaInfo.none.rawValue)!
let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceGray(), colors: [CGColor(gray: 0, alpha: 1), CGColor(gray: 1, alpha: 1)] as CFArray, locations: [0, 1])!
maskCtx.setFillColor(CGColor(gray: 1, alpha: 1)); maskCtx.fill(CGRect(x: 0, y: dest.minY + fade, width: CGFloat(W), height: dest.height - 2 * fade))
maskCtx.saveGState(); maskCtx.clip(to: CGRect(x: 0, y: dest.minY, width: CGFloat(W), height: fade))
maskCtx.drawLinearGradient(grad, start: CGPoint(x: 0, y: dest.minY), end: CGPoint(x: 0, y: dest.minY + fade), options: []); maskCtx.restoreGState()
maskCtx.saveGState(); maskCtx.clip(to: CGRect(x: 0, y: dest.maxY - fade, width: CGFloat(W), height: fade))
maskCtx.drawLinearGradient(grad, start: CGPoint(x: 0, y: dest.maxY), end: CGPoint(x: 0, y: dest.maxY - fade), options: []); maskCtx.restoreGState()
ctx.draw(layer.makeImage()!.masking(maskCtx.makeImage()!)!, in: CGRect(x: 0, y: 0, width: W, height: W))
// A hairline inner edge so the dark shape reads on a dark Dock.
ctx.resetClip()
ctx.addPath(CGPath(roundedRect: box.insetBy(dx: 1, dy: 1), cornerWidth: 184, cornerHeight: 184, transform: nil))
ctx.setStrokeColor(CGColor(gray: 1, alpha: 0.10)); ctx.setLineWidth(2); ctx.strokePath()
let out = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! out.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
