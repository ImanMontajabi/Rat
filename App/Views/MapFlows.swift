import SwiftUI
import MapKit
import AppKit

/// Which way a line on the map carries traffic now: up (this Mac sends), down (it receives), both (a duplex
/// connection such as a WebSocket or a call), or idle. Decided from the bytes per second of the connections it
/// stands for, on the last pass.
enum FlowDirection: String, Equatable {
    case idle, up, down, both

    /// A direction counts once it moves this many bytes per second (keep-alives and ACKs stay below it).
    static let activeRate = 512.0
    /// One direction is "the" direction when it carries this many times the other (a download's ACKs go up).
    static let dominance = 4.0

    init(rateIn: Double, rateOut: Double) {
        let down = rateIn >= Self.activeRate, up = rateOut >= Self.activeRate
        switch (up, down) {
        case (false, false): self = .idle
        case (true, false): self = .up
        case (false, true): self = .down
        case (true, true): self = rateOut >= rateIn * Self.dominance ? .up : rateIn >= rateOut * Self.dominance ? .down : .both
        }
    }
}

/// The moving pulses on the map's lines: when they run, where a pulse is, and how they look.
enum MapFlows {
    /// The frame rate while pulses move (the map itself draws only when it changes).
    static let framesPerSecond = 30.0
    /// Seconds for a pulse to travel a whole line, whatever its length.
    static let travelTime = 2.4
    /// Above this many bytes per second a line carries two pulses each way.
    static let fastRate = 256.0 * 1024

    static let sent = Color(red: 0.78, green: 0.47, blue: 1.0)       // the purple of the "sent" pill, brighter
    static let received = Color(red: 0.36, green: 0.66, blue: 1.0)   // the blue of the "received" pill, brighter

    /// Pulses run only while someone can see them and something moves: the window is on screen (not covered,
    /// minimized or hidden), Reduce Motion is off, and at least one line carries traffic. Otherwise no frame is drawn.
    static func animates(visible: Bool, reduceMotion: Bool, flows: [FlowDirection]) -> Bool {
        visible && !reduceMotion && flows.contains { $0 != .idle }
    }

    /// For VoiceOver and the UI tests: "3 moving", "paused" (traffic, nobody looking), or "idle".
    static func summary(flows: [FlowDirection], animating: Bool) -> String {
        let moving = flows.filter { $0 != .idle }.count
        return moving == 0 ? "idle" : animating ? "\(moving) moving" : "paused"
    }

    /// Where along a line a pulse is at `time`: 0 at the start, 1 at the end, the same for every line.
    static func phase(time: TimeInterval, offset: Double = 0) -> Double {
        let p = (time / travelTime + offset).truncatingRemainder(dividingBy: 1)
        return p < 0 ? p + 1 : p
    }

    /// The pulses of one line: up runs from the line's start (this Mac, or the proxy server for a proxied hop) to
    /// its end, down the other way, both runs one of each, half a line apart; a fast line has twice as many.
    static func runs(flow: FlowDirection, fast: Bool) -> [(reverse: Bool, offset: Double, sent: Bool)] {
        var runs: [(reverse: Bool, offset: Double, sent: Bool)]
        switch flow {
        case .idle: return []
        case .up: runs = [(false, 0, true)]
        case .down: runs = [(true, 0, false)]
        case .both: runs = [(false, 0, true), (true, 0.5, false)]
        }
        if fast { runs += runs.map { ($0.reverse, $0.offset + (flow == .both ? 0.25 : 0.5), $0.sent) } }
        return runs
    }
}

/// Camera moves of the map, for the pulses to follow. MapPane keeps it without observing it, so a pan redraws the
/// pulses, not the map's pins and lines.
@MainActor
final class MapCameraTicks: ObservableObject {
    @Published var version = 0
}

/// The moving pulses over the map's lines. Each pulse is a small Core Animation layer that a repeating keyframe
/// animation moves along its line's screen path, at `MapFlows.framesPerSecond` at most: the render server runs it
/// and the app does no work per frame. The paths come from the map (`MapProxy`) and are rebuilt only when the camera
/// moves or a line's traffic changes. Paused, there are no layers and no frames.
struct FlowOverlay: View {
    struct Line: Identifiable { let id: String; let coords: [CLLocationCoordinate2D]; let flow: FlowDirection; let fast: Bool }
    @ObservedObject var camera: MapCameraTicks
    let lines: [Line]
    let proxy: MapProxy
    let paused: Bool
    static let space = "rat-map"

    var body: some View {
        let _ = camera.version
        let tracks = paused ? [] : lines.map { l in
            PulseLayerView.Track(id: l.id, points: l.coords.compactMap { proxy.convert($0, to: .named(Self.space)) }, flow: l.flow, fast: l.fast)
        }
        PulseLayerView(tracks: tracks).allowsHitTesting(false)
    }
}

struct PulseLayerView: NSViewRepresentable {
    struct Track: Equatable { let id: String; let points: [CGPoint]; let flow: FlowDirection; let fast: Bool }
    let tracks: [Track]

    func makeNSView(context: Context) -> PulseHost { PulseHost() }
    func updateNSView(_ v: PulseHost, context: Context) { v.show(tracks) }
}

/// The layers of `PulseLayerView`.
final class PulseHost: NSView {
    private var shown: [String: (track: PulseLayerView.Track, layers: [CALayer])] = [:]

    override init(frame: NSRect) {
        super.init(frame: frame)
        layer = CALayer()
        wantsLayer = true
    }
    /// SwiftUI's points have a top-left origin; a flipped view gives its layers the same.
    override var isFlipped: Bool { true }
    required init?(coder: NSCoder) { fatalError("not used") }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    /// Layers currently animating (for tests).
    var pulseCount: Int { shown.values.reduce(0) { $0 + $1.layers.count } }

    func show(_ tracks: [PulseLayerView.Track]) {
        let wanted = Dictionary(tracks.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for (id, s) in shown where wanted[id] != s.track {
            s.layers.forEach { $0.removeFromSuperlayer() }
            shown[id] = nil
        }
        CATransaction.begin(); CATransaction.setDisableActions(true)
        for t in tracks where shown[t.id] == nil && t.points.count > 1 {
            let layers = Self.pulses(for: t)
            layers.forEach { layer?.addSublayer($0) }
            shown[t.id] = (t, layers)
        }
        CATransaction.commit()
    }

    static func pulses(for t: PulseLayerView.Track) -> [CALayer] {
        let forward = CGMutablePath(), backward = CGMutablePath()
        forward.addLines(between: t.points); backward.addLines(between: t.points.reversed())
        let now = CACurrentMediaTime()
        var out: [CALayer] = []
        for run in MapFlows.runs(flow: t.flow, fast: t.fast) {
            let color = NSColor(run.sent ? MapFlows.sent : MapFlows.received)
            // The head, then a short fading trail just behind it on the same path.
            for (k, lag) in [0.0, 0.025, 0.05, 0.075].enumerated() {
                let dot = k == 0 ? glow(color) : trail(color, size: 5 - CGFloat(k), opacity: Float(0.5 - Double(k) * 0.13))
                let move = CAKeyframeAnimation(keyPath: "position")
                move.path = run.reverse ? backward : forward
                move.calculationMode = .paced
                move.duration = MapFlows.travelTime
                move.repeatCount = .infinity
                // Started in the past so every pulse is where `MapFlows.phase` says, whenever it was added.
                move.beginTime = now - MapFlows.phase(time: now, offset: run.offset - lag) * MapFlows.travelTime
                move.preferredFrameRateRange = CAFrameRateRange(minimum: 24, maximum: Float(MapFlows.framesPerSecond), preferred: Float(MapFlows.framesPerSecond))
                dot.add(move, forKey: "flow")
                out.append(dot)
            }
        }
        return out
    }

    /// A bright core in a soft halo: a shadow with an explicit path, which the render server draws cheaply.
    private static func glow(_ color: NSColor) -> CALayer {
        let dot = CALayer()
        dot.bounds = CGRect(x: 0, y: 0, width: 8, height: 8)
        dot.cornerRadius = 4
        dot.backgroundColor = color.cgColor
        dot.borderColor = NSColor.white.withAlphaComponent(0.85).cgColor
        dot.borderWidth = 1.2
        dot.shadowColor = color.cgColor
        dot.shadowOpacity = 0.9
        dot.shadowRadius = 6
        dot.shadowOffset = .zero
        dot.shadowPath = CGPath(ellipseIn: dot.bounds.insetBy(dx: -3, dy: -3), transform: nil)
        return dot
    }

    private static func trail(_ color: NSColor, size: CGFloat, opacity: Float) -> CALayer {
        let dot = CALayer()
        dot.bounds = CGRect(x: 0, y: 0, width: size, height: size)
        dot.cornerRadius = size / 2
        dot.backgroundColor = color.cgColor
        dot.opacity = opacity
        return dot
    }
}

/// Whether the window that shows a view can be seen: on screen and not fully covered, not minimized, and the app
/// not hidden (`NSWindow.occlusionState`, which macOS updates for all three).
@MainActor
final class WindowVisibility: ObservableObject {
    @Published private(set) var visible = true
    private weak var window: NSWindow?
    private var observers: [NSObjectProtocol] = []

    func attach(_ w: NSWindow?) {
        guard w !== window else { return }
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = []
        window = w
        guard let w else { return }
        for name in [NSWindow.didChangeOcclusionStateNotification, NSWindow.didMiniaturizeNotification, NSWindow.didDeminiaturizeNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: w, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.update() }
            })
        }
        update()
    }

    private func update() {
        guard let w = window else { return }
        let now = w.occlusionState.contains(.visible) && !w.isMiniaturized
        if now != visible { visible = now }
    }
}

/// Hands the hosting window to a `WindowVisibility`.
struct WindowVisibilityReader: NSViewRepresentable {
    let visibility: WindowVisibility

    final class Probe: NSView {
        var onWindow: ((NSWindow?) -> Void)?
        override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); onWindow?(window) }
    }

    func makeNSView(context: Context) -> Probe {
        let v = Probe()
        v.onWindow = { [visibility] w in Task { @MainActor in visibility.attach(w) } }
        return v
    }

    func updateNSView(_ v: Probe, context: Context) {}
}
