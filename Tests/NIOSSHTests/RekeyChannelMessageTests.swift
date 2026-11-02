//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// What a client owes its child channels around a server-initiated key exchange, at the 32 KiB packet size a
/// terminal client uses. Between the peer's KEXINIT and our NEWKEYS no channel message may leave, and each kind of
/// message loses something different if it is refused instead of held: data, receive credit, send credit, an open
/// that never completes, or a close the peer never hears.
final class RekeyChannelMessageTests: XCTestCase {
    enum HostKeyError: Error { case rejected }

    final class Recorder: ChannelInboundHandler {
        typealias InboundIn = SSHChannelData
        var bytes = 0
        var payloads: [String] = []
        var inputClosed = false

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let message = self.unwrapInboundIn(data)
            self.bytes += message.data.readableBytes
            if case .byteBuffer(let buffer) = message.data, buffer.readableBytes < 100 {
                self.payloads.append(String(buffer: buffer))
            }
        }

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if case ChannelEvent.inputClosed = event { self.inputClosed = true }
            context.fireUserInboundEventTriggered(event)
        }
    }

    final class Completion {
        var result: Result<Void, Error>?

        var succeeded: Bool {
            if case .success = self.result { return true }
            return false
        }

        var failed: Bool {
            if case .failure = self.result { return true }
            return false
        }
    }

    final class GatedHostKeys: NIOSSHClientServerAuthenticationDelegate {
        var holdNext = false
        var rejectNext = false
        var held: EventLoopPromise<Void>?

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            if self.rejectNext {
                validationCompletePromise.fail(HostKeyError.rejected)
            } else if self.holdNext {
                self.held = validationCompletePromise
            } else {
                validationCompletePromise.succeed(())
            }
        }
    }

    final class CloseOnError: ChannelInboundHandler {
        typealias InboundIn = Any

        func errorCaught(context: ChannelHandlerContext, error: Error) {
            context.close(promise: nil)
        }
    }

    final class RequestRecorder: ChannelInboundHandler {
        typealias InboundIn = Any
        var windowChanges = 0

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if event is SSHChannelRequestEvent.WindowChangeRequest { self.windowChanges += 1 }
            context.fireUserInboundEventTriggered(event)
        }
    }

    private static let packetSize = 32768

    var pair: BackToBackEmbeddedChannel!
    var client: Channel!
    var server: Channel!
    var clientReads: Recorder!
    var serverReads: Recorder!
    let hostKeys = GatedHostKeys()
    let window = RekeyChannelMessageTests.packetSize * Constants.channelWindowSizePacketMultiple

    override func setUpWithError() throws {
        self.pair = BackToBackEmbeddedChannel()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = self.hostKeys
        try self.pair.configureWithHarness(harness, clientMaximumPacketSize: Self.packetSize)
        try self.pair.activate()
        try self.pair.interactInMemory()
        self.client = try self.pair.createNewChannel()
        try self.pair.interactInMemory()
        self.server = try XCTUnwrap(self.pair.activeServerChannels.first)
        self.clientReads = Recorder()
        self.serverReads = Recorder()
        try self.client.pipeline.syncOperations.addHandler(self.clientReads)
        try self.server.pipeline.syncOperations.addHandler(self.serverReads)
    }

    @discardableResult
    private func write(_ channel: Channel, _ count: Int, byte: UInt8 = 65) -> Completion {
        self.tracked(channel) { promise in
            let data = ByteBuffer(repeating: byte, count: count)
            channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(data)), promise: promise)
        }
    }

    private func tracked(_ channel: Channel, _ start: (EventLoopPromise<Void>) -> Void) -> Completion {
        let completion = Completion()
        let promise = channel.eventLoop.makePromise(of: Void.self)
        let box = NIOLoopBoundBox(completion, eventLoop: channel.eventLoop)
        promise.futureResult.whenComplete { box.value.result = $0 }
        start(promise)
        return completion
    }

    /// Delivers what the server has written, in one network read or one per packet, without running the rest of
    /// the exchange.
    private func deliverServerOutput(coalesced: Bool) throws {
        if coalesced {
            var batch = ByteBuffer()
            while let item = try self.pair.server.readOutbound(as: IOData.self) {
                guard case .byteBuffer(var buffer) = item else { return XCTFail("Unexpected file region") }
                batch.writeBuffer(&buffer)
            }
            if batch.readableBytes > 0 { try self.pair.client.writeInbound(batch) }
        } else {
            while let item = try self.pair.server.readOutbound(as: IOData.self) {
                try self.pair.client.writeInbound(item)
            }
        }
    }

    /// Leaves the client having seen KEXINIT and not yet having sent NEWKEYS: only key exchange may leave it.
    private func enterKeyExchange() throws {
        try self.pair.serverSSHHandler!._rekey()
        try self.deliverServerOutput(coalesced: true)
    }

    private func createChannel() -> NIOLoopBoundBox<Bool?> {
        let created = NIOLoopBoundBox<Bool?>(nil, eventLoop: self.client.eventLoop)
        let promise = self.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenComplete { result in
            if case .success = result { created.value = true } else { created.value = false }
        }
        self.pair.clientSSHHandler!.createChannel(promise, nil)
        return created
    }

    // MARK: Boundaries of the forbidden interval

    func testWriteBeforeTheClientSeesKexInitAndAfterTheExchangeGoStraightOut() throws {
        try self.pair.serverSSHHandler!._rekey()
        let before = self.write(self.client, 6, byte: 66)
        try self.pair.interactInMemory()
        let after = self.write(self.client, 5, byte: 67)
        try self.pair.interactInMemory()
        XCTAssertTrue(before.succeeded)
        XCTAssertTrue(after.succeeded)
        XCTAssertEqual(self.serverReads.payloads, ["BBBBBB", "CCCCC"])
    }

    // MARK: Operations started during a key exchange

    func testDataWaitsAndArrivesInOrder() throws {
        try self.enterKeyExchange()
        let first = self.write(self.client, 4, byte: 65)
        let second = self.write(self.client, 3, byte: 66)
        XCTAssertNil(first.result, "must wait for NEWKEYS, neither fail nor claim delivery")
        XCTAssertNil(second.result)
        try self.pair.interactInMemory()
        XCTAssertTrue(first.succeeded)
        XCTAssertTrue(second.succeeded)
        XCTAssertEqual(self.serverReads.payloads, ["AAAA", "BBB"])
    }

    func testAWriteFromAHeldWritesCallbackStaysBehindTheQueue() throws {
        try self.enterKeyExchange()
        let later = NIOLoopBoundBox<Completion?>(nil, eventLoop: self.client.eventLoop)
        let bound = NIOLoopBoundBox(self, eventLoop: self.client.eventLoop)
        let first = self.client.eventLoop.makePromise(of: Void.self)
        first.futureResult.whenSuccess {
            later.value = bound.value.write(bound.value.client, 1, byte: 67)
        }
        let data = ByteBuffer(repeating: 65, count: 1)
        self.client.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(data)), promise: first)
        let second = self.write(self.client, 1, byte: 66)
        XCTAssertNil(second.result)
        try self.pair.interactInMemory()
        XCTAssertEqual(self.serverReads.payloads, ["A", "B", "C"])
        XCTAssertTrue(second.succeeded)
        XCTAssertEqual(later.value?.succeeded, true)
    }

    func testWindowChangeArrives() throws {
        let requests = RequestRecorder()
        try self.server.pipeline.syncOperations.addHandler(requests)
        try self.enterKeyExchange()
        let sent = self.tracked(self.client) { promise in
            self.client.triggerUserOutboundEvent(
                SSHChannelRequestEvent.WindowChangeRequest(
                    terminalCharacterWidth: 123,
                    terminalRowHeight: 45,
                    terminalPixelWidth: 0,
                    terminalPixelHeight: 0
                ),
                promise: promise
            )
        }
        try self.pair.interactInMemory()
        XCTAssertTrue(sent.succeeded)
        XCTAssertEqual(requests.windowChanges, 1)
    }

    func testChannelOpenCompletes() throws {
        try self.enterKeyExchange()
        let created = self.createChannel()
        try self.pair.interactInMemory()
        XCTAssertEqual(created.value, true)
        XCTAssertEqual(self.pair.activeServerChannels.count, 2)
    }

    func testEOFArrives() throws {
        try self.server.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).wait()
        try self.enterKeyExchange()
        let finished = self.tracked(self.client) { self.client.close(mode: .output, promise: $0) }
        try self.pair.interactInMemory()
        XCTAssertTrue(finished.succeeded)
        XCTAssertTrue(self.serverReads.inputClosed)
    }

    func testCloseCompletesAndTheConnectionStaysUsable() throws {
        try self.enterKeyExchange()
        let closed = self.tracked(self.client) { self.client.close(promise: $0) }
        try self.pair.interactInMemory()
        self.pair.run()
        XCTAssertTrue(closed.succeeded, "a close completes only once the peer has heard it")
        XCTAssertEqual(self.pair.activeServerChannels.count, 0)
        let another = try self.pair.createNewChannel()
        try self.pair.interactInMemory()
        XCTAssertTrue(another.isActive)
    }

    /// The child has gone before our NEWKEYS can leave, so its reply has to outlive it.
    func testACloseReplyOutlivesItsChild() throws {
        self.hostKeys.holdNext = true
        try self.pair.serverSSHHandler!._rekey()
        try self.pair.interactInMemory()
        XCTAssertNotNil(self.hostKeys.held)
        self.server.close(promise: nil)
        try self.pair.interactInMemory()
        self.pair.run()
        XCTAssertFalse(self.client.isActive)
        XCTAssertEqual(self.pair.activeServerChannels.count, 1, "the reply must wait for NEWKEYS")
        self.hostKeys.held!.succeed(())
        try self.pair.interactInMemory()
        self.pair.run()
        XCTAssertEqual(self.pair.activeServerChannels.count, 0)
    }

    // MARK: Receive window

    private func deliverData(_ count: Int, thenKexInitCoalesced coalesced: Bool) throws {
        self.write(self.server, count)
        try self.pair.serverSSHHandler!._rekey()
        try self.deliverServerOutput(coalesced: coalesced)
        try self.pair.interactInMemory()
    }

    func testFullWindowInTheSameReadAsKexInit() throws {
        try self.deliverData(self.window, thenKexInitCoalesced: true)
        let probe = self.write(self.server, 1, byte: 90)
        try self.pair.interactInMemory()
        XCTAssertTrue(probe.succeeded)
        XCTAssertEqual(self.clientReads.bytes, self.window + 1)
    }

    /// Terminal output doesn't line up with whole packets, so an adjust usually comes a little past the half window.
    /// Losing just that one leaves the peer short of the point where we would send another.
    func testOneAdjustJustOverHalfTheWindow() throws {
        self.write(self.server, 1000)
        try self.pair.interactInMemory()
        try self.deliverData(self.window / 2, thenKexInitCoalesced: true)
        let probe = self.write(self.server, self.window, byte: 90)
        try self.pair.interactInMemory()
        XCTAssertTrue(probe.succeeded)
        XCTAssertEqual(self.clientReads.bytes, 1000 + self.window / 2 + self.window)
    }

    func testDemandReadDuringTheExchange() throws {
        try self.client.setOption(ChannelOptions.autoRead, value: false).wait()
        self.write(self.server, 1)
        try self.pair.interactInMemory()
        self.client.read()
        self.write(self.server, self.window - 1)
        try self.deliverServerOutput(coalesced: false)
        try self.pair.serverSSHHandler!._rekey()
        try self.deliverServerOutput(coalesced: false)
        self.client.read()
        XCTAssertEqual(self.clientReads.bytes, self.window)
        try self.pair.interactInMemory()
        let probe = self.write(self.server, 1, byte: 90)
        self.client.read()
        try self.pair.interactInMemory()
        XCTAssertTrue(probe.succeeded)
    }

    /// The peer has no window left, so nothing more can arrive to prompt a replacement adjust.
    func testLastBufferedReadWithTheWindowExhausted() throws {
        try self.client.setOption(ChannelOptions.autoRead, value: false).wait()
        self.write(self.server, self.window)
        try self.pair.interactInMemory()
        try self.enterKeyExchange()
        self.client.read()
        XCTAssertEqual(self.clientReads.bytes, self.window)
        try self.pair.interactInMemory()
        let probe = self.write(self.server, 1, byte: 90)
        try self.pair.interactInMemory()
        self.client.read()
        try self.pair.interactInMemory()
        XCTAssertTrue(probe.succeeded)
        XCTAssertEqual(self.clientReads.bytes, self.window + 1)
    }

    // MARK: Send window

    func testHeldWritesDoNotShrinkTheSendWindow() throws {
        for round in 0..<70 {
            try self.enterKeyExchange()
            self.write(self.client, Self.packetSize, byte: UInt8(round))
            try self.pair.interactInMemory()
        }
        let probe = self.write(self.client, 1, byte: 90)
        try self.pair.interactInMemory()
        XCTAssertTrue(probe.succeeded)
        XCTAssertEqual(self.serverReads.bytes, 70 * Self.packetSize + 1)
    }

    // MARK: Lifecycle

    func testConnectionLossFailsWhatWaits() throws {
        try self.enterKeyExchange()
        let waiting = self.write(self.client, 4)
        XCTAssertNil(waiting.result)
        let created = self.createChannel()
        self.pair.client.close(promise: nil)
        self.pair.run()
        try? self.pair.interactInMemory()
        self.pair.run()
        XCTAssertTrue(waiting.failed)
        XCTAssertEqual(created.value, false)
    }

    /// A failed key exchange reaches the pipeline as an error and doesn't close the connection, so held writes wait
    /// until whoever owns the connection closes it.
    func testRejectedHostKeyHoldsWritesUntilTheConnectionCloses() throws {
        self.hostKeys.rejectNext = true
        try self.pair.serverSSHHandler!._rekey()
        try self.deliverServerOutput(coalesced: true)
        let waiting = self.write(self.client, 4)
        XCTAssertThrowsError(try self.pair.interactInMemory())
        try? self.pair.interactInMemory()
        XCTAssertNil(waiting.result)
        XCTAssertTrue(self.pair.client.isActive)
        self.pair.client.close(promise: nil)
        self.pair.run()
        XCTAssertTrue(waiting.failed)
    }

    func testClosingOnErrorSettlesWritesHeldByARejectedHostKey() throws {
        try self.pair.client.pipeline.syncOperations.addHandler(CloseOnError())
        self.hostKeys.rejectNext = true
        try self.pair.serverSSHHandler!._rekey()
        try self.deliverServerOutput(coalesced: true)
        let waiting = self.write(self.client, 4)
        try? self.pair.interactInMemory()
        self.pair.run()
        XCTAssertTrue(waiting.failed)
        XCTAssertFalse(self.pair.client.isActive)
    }

    // MARK: Under traffic

    func testManyExchangesAtVaryingBoundaries() throws {
        var sentByServer = 0
        var sentByClient = 0
        for round in 1...200 {
            let down = (round * 7919) % (self.window / 3) + 1
            let up = (round * 104_729) % Self.packetSize + 1
            self.write(self.server, down)
            sentByServer += down
            try self.pair.serverSSHHandler!._rekey()
            try self.deliverServerOutput(coalesced: round.isMultiple(of: 2))
            self.write(self.client, up)
            sentByClient += up
            try self.pair.interactInMemory()
        }
        let down = self.write(self.server, self.window, byte: 90)
        let up = self.write(self.client, Self.packetSize * 8, byte: 90)
        try self.pair.interactInMemory()
        XCTAssertTrue(down.succeeded)
        XCTAssertTrue(up.succeeded)
        XCTAssertEqual(self.clientReads.bytes, sentByServer + self.window)
        XCTAssertEqual(self.serverReads.bytes, sentByClient + Self.packetSize * 8)
    }
}
