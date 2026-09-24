// Resizes the supplied Slipstream logo (app/Icon.png) into the shipped Home Screen icons
// and stamps each with its provenance. Run from the repository root: swift app/Icon.swift app/Assets
import CoreGraphics
import Foundation
import ImageIO

let directory = CommandLine.arguments[1]
let logo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Icon.png")
let provenance = "Origin: Anson's supplied Slipstream logo (app/Icon.png), resized by app/Icon.swift; artwork unmodified."
guard let source = CGImageSourceCreateWithURL(logo as CFURL, nil), let image = CGImageSourceCreateImageAtIndex(source, 0, nil),
      image.width == image.height else { fatalError("app/Icon.png must be a square image") }

func crc32(_ bytes: [UInt8]) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in bytes {
        crc ^= UInt32(byte)
        for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
    }
    return ~crc
}
func bigEndian(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.bigEndian, Array.init) }

for (name, size) in [("Icon60@2x", 120), ("Icon60@3x", 180)] {
    // Opaque RGB: iOS icons carry no alpha channel.
    let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
    context.interpolationQuality = .high
    context.draw(image, in: CGRect(x: 0, y: 0, width: size, height: size))
    let data = NSMutableData()
    let destination = CGImageDestinationCreateWithData(data, "public.png" as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context.makeImage()!, nil)
    guard CGImageDestinationFinalize(destination) else { fatalError("Could not encode \(name)") }
    // A tEXt chunk directly after IHDR (8-byte signature + 25-byte IHDR chunk) records where the art came from.
    let body = Array("tEXt".utf8) + Array("impeccable:prompt".utf8) + [0] + Array(provenance.utf8)
    var png = [UInt8](data as Data)
    png.insert(contentsOf: bigEndian(UInt32(body.count - 4)) + body + bigEndian(crc32(body)), at: 33)
    try Data(png).write(to: URL(fileURLWithPath: "\(directory)/\(name).png"))
}
