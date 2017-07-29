package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StopWaitingManager", func() {
	var manager *stopWaitingManager
	BeforeEach(func() {
		manager = &stopWaitingManager{}
	})

	It("returns nil in the beginning", func() {
		Expect(manager.GetStopWaitingFrame(false)).To(BeNil())
		Expect(manager.GetStopWaitingFrame(true)).To(BeNil())
	})

	It("returns a StopWaitingFrame, when a new ACK arrives", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		Expect(manager.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 11}))
	})

	It("does not decrease the LeastUnacked", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 9})
		Expect(manager.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 11}))
	})

	It("does not send the same StopWaitingFrame twice", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		Expect(manager.GetStopWaitingFrame(false)).ToNot(BeNil())
		Expect(manager.GetStopWaitingFrame(false)).To(BeNil())
	})

	It("gets the same StopWaitingFrame twice, if forced", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		Expect(manager.GetStopWaitingFrame(false)).ToNot(BeNil())
		Expect(manager.GetStopWaitingFrame(true)).ToNot(BeNil())
		Expect(manager.GetStopWaitingFrame(true)).ToNot(BeNil())
	})

	It("increases the LeastUnacked when a retransmission is queued", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		manager.QueuedRetransmissionForPacketNumber(20)
		Expect(manager.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 21}))
	})

	It("does not decrease the LeastUnacked when a retransmission is queued", func() {
		manager.ReceivedAck(&frames.AckFrame{LargestAcked: 10})
		manager.QueuedRetransmissionForPacketNumber(9)
		Expect(manager.GetStopWaitingFrame(false)).To(Equal(&frames.StopWaitingFrame{LeastUnacked: 11}))
	})
})
