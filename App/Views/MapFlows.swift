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

    /// The laser tracer that carries a pulse: within one `travelTime` its head crosses the line by `arrival`, its
    /// tail drains into the far end behind it, and a ring ripples out there from `arrival` to the end of the cycle.
    enum Tracer {
        /// Share of the cycle the head takes to cross the line; the rest is the tail landing and the ripple.
        static let arrival = 0.8
        /// The beam's tail, as a share of the line's length (at most `1 / arrival - 1`, so it has landed by the end).
        static let beamTail = 0.22
        /// The white-hot core just behind the head.
        static let coreTail = 0.05

        /// Keyframes of a stroke with `tail`: its end (the head) runs 0 → 1 until `arrival` and waits there; its start
        /// stays at 0 until the head is `tail` along, then follows it at the same speed until it reaches 1 too.
        static func strokeEnd() -> (values: [Double], times: [Double]) { ([0, 1, 1], [0, arrival, 1]) }
        static func strokeStart(tail: Double) -> (values: [Double], times: [Double]) {
            ([0, 0, 1, 1], [0, tail * arrival, min(1, (1 + tail) * arrival), 1])
        }

        /// Where the stroke's head and the start of its tail are at `t` (0...1 of the cycle), from those keyframes.
        static func stroke(at t: Double, tail: Double) -> (start: Double, end: Double) {
            func value(_ k: (values: [Double], times: [Double])) -> Double {
                guard let i = k.times.indices.dropFirst().first(where: { k.times[$0] >= t }) else { return k.values.last! }
                let span = k.times[i] - k.times[i - 1]
                let f = span > 0 ? (t - k.times[i - 1]) / span : 1
                return k.values[i - 1] + (k.values[i] - k.values[i - 1]) * f
            }
            return (value(strokeStart(tail: tail)), value(strokeEnd()))
        }
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
    private var settle: DispatchWorkItem?

    /// The map's size changed. It takes the new size after this layout pass, and during an animated resize (the
    /// inspector sliding in or out) only at the end, so the pulses follow on the next turn of the main queue and
    /// again once the size has stopped changing for `settleDelay`.
    func resized() {
        DispatchQueue.main.async { [weak self] in self?.version &+= 1 }
        settle?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.version &+= 1 }
        settle = w
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.settleDelay, execute: w)
    }
    static let settleDelay = 0.3
}

/// The moving pulses over the map's lines. Each pulse is a laser tracer (`PulseHost.pulses`) of a few Core Animation
/// layers that a repeating animation moves along its line's screen path, at `MapFlows.framesPerSecond` at most: the
/// render server runs it and the app does no work per frame. They are clipped to the map. The paths come from the map (`MapProxy`) and are rebuilt only when the camera
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
            // A resize moves every point on screen without moving the camera (the window growing to its restored
            // size at launch, the inspector shown or hidden): the paths are converted again (`resized`).
            .onGeometryChange(for: CGSize.self) { $0.size } action: { _ in camera.resized() }
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
        // A line to a server off the map's edge runs on under the list and the inspector: its tracers stop at the edge.
        layer?.masksToBounds = true
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

    /// Each pulse is a laser tracer, like the attack maps of hacker films: a soft wide glow and a bright beam with a
    /// fading tail, a white-hot core and a haloed head racing along the line, and a ring that ripples out where it
    /// lands. Five layers a pulse, all moved by the render server (`MapFlows.Tracer` has the timing).
    static func pulses(for t: PulseLayerView.Track) -> [CALayer] {
        let forward = CGMutablePath(), backward = CGMutablePath()
        forward.addLines(between: t.points); backward.addLines(between: t.points.reversed())
        let now = CACurrentMediaTime()
        var out: [CALayer] = []
        for run in MapFlows.runs(flow: t.flow, fast: t.fast) {
            let color = NSColor(run.sent ? MapFlows.sent : MapFlows.received)
            let path = run.reverse ? backward : forward
            // Started in the past so every pulse is where `MapFlows.phase` says, whenever it was added.
            let begin = now - MapFlows.phase(time: now, offset: run.offset) * MapFlows.travelTime
            let layers: [(CALayer, [CAAnimation])] = [
                beam(path, color: color.withAlphaComponent(0.28), width: 7, tail: MapFlows.Tracer.beamTail),
                beam(path, color: color, width: 2.4, tail: MapFlows.Tracer.beamTail * 0.8),
                beam(path, color: NSColor.white.withAlphaComponent(0.95), width: 1.4, tail: MapFlows.Tracer.coreTail),
                head(path, color: color),
                ripple(at: (run.reverse ? t.points.first : t.points.last) ?? .zero, color: color),
            ]
            for (layer, animations) in layers {
                let cycle = CAAnimationGroup()
                cycle.animations = animations
                cycle.duration = MapFlows.travelTime
                cycle.repeatCount = .infinity
                cycle.beginTime = begin
                cycle.preferredFrameRateRange = CAFrameRateRange(minimum: 24, maximum: Float(MapFlows.framesPerSecond), preferred: Float(MapFlows.framesPerSecond))
                layer.add(cycle, forKey: "flow")
                out.append(layer)
            }
        }
        return out
    }

    private static func keyframes(_ keyPath: String, _ k: (values: [Double], times: [Double])) -> CAKeyframeAnimation {
        let a = CAKeyframeAnimation(keyPath: keyPath)
        a.values = k.values
        a.keyTimes = k.times.map { NSNumber(value: $0) }
        a.duration = MapFlows.travelTime
        return a
    }

    /// One stroke of the beam: the line's path, drawn only between the tail and the head.
    private static func beam(_ path: CGPath, color: NSColor, width: CGFloat, tail: Double) -> (CALayer, [CAAnimation]) {
        let l = CAShapeLayer()
        l.anchorPoint = .zero; l.bounds = .zero; l.position = .zero
        l.path = path
        l.fillColor = nil
        l.strokeColor = color.cgColor
        l.lineWidth = width
        l.lineCap = .round
        l.lineJoin = .round
        l.strokeStart = 1; l.strokeEnd = 1   // between cycles nothing shows
        return (l, [keyframes("strokeEnd", MapFlows.Tracer.strokeEnd()), keyframes("strokeStart", MapFlows.Tracer.strokeStart(tail: tail))])
    }

    /// The head: a bright core in a soft halo (a shadow with an explicit path, which the render server draws cheaply),
    /// on the beam's tip until it lands.
    private static func head(_ path: CGPath, color: NSColor) -> (CALayer, [CAAnimation]) {
        let dot = CALayer()
        dot.bounds = CGRect(x: 0, y: 0, width: 6, height: 6)
        dot.cornerRadius = 3
        dot.backgroundColor = NSColor.white.cgColor
        dot.shadowColor = color.cgColor
        dot.shadowOpacity = 1
        dot.shadowRadius = 7
        dot.shadowOffset = .zero
        dot.shadowPath = CGPath(ellipseIn: dot.bounds.insetBy(dx: -4, dy: -4), transform: nil)
        dot.opacity = 0
        let move = CAKeyframeAnimation(keyPath: "position")
        move.path = path
        move.calculationMode = .paced
        move.duration = MapFlows.travelTime * MapFlows.Tracer.arrival
        move.fillMode = .forwards
        let a = MapFlows.Tracer.arrival
        let shown = keyframes("opacity", ([1, 1, 0, 0], [0, a, min(1, a + 0.02), 1]))
        return (dot, [move, shown])
    }

    /// The ring where the tracer lands: it grows and fades between `arrival` and the end of the cycle.
    private static func ripple(at point: CGPoint, color: NSColor) -> (CALayer, [CAAnimation]) {
        let ring = CAShapeLayer()
        ring.bounds = .zero
        ring.position = point
        ring.path = CGPath(ellipseIn: CGRect(x: -6, y: -6, width: 12, height: 12), transform: nil)
        ring.fillColor = color.withAlphaComponent(0.18).cgColor
        ring.strokeColor = color.cgColor
        ring.lineWidth = 1.5
        ring.opacity = 0
        let a = MapFlows.Tracer.arrival
        let grow = keyframes("transform.scale", ([0.3, 0.3, 2.6], [0, a, 1]))
        let fade = keyframes("opacity", ([0, 0, 0.95, 0], [0, a, min(1, a + 0.03), 1]))
        return (ring, [grow, fade])
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
