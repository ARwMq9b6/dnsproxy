package crypto

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Source Address Tokens", func() {
	It("should generate the encryption key", func() {
		Expect(deriveKey([]byte("TESTING"))).To(Equal([]byte{0xee, 0x71, 0x18, 0x9, 0xfd, 0xb8, 0x9a, 0x79, 0x19, 0xfc, 0x5e, 0x1a, 0x97, 0x20, 0xb2, 0x6}))
	})

	Context("tokens", func() {
		It("serializes", func() {
			ip := []byte{127, 0, 0, 1}
			token := &sourceAddressToken{sourceAddr: ip, timestamp: 0xdeadbeef}
			Expect(token.serialize()).To(Equal([]byte{
				0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
				127, 0, 0, 1,
			}))
		})

		It("reads", func() {
			token, err := parseToken([]byte{
				0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
				127, 0, 0, 1,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(token.sourceAddr).To(Equal([]byte{127, 0, 0, 1}))
			Expect(token.timestamp).To(Equal(uint64(0xdeadbeef)))
		})

		It("rejects tokens of wrong size", func() {
			_, err := parseToken(nil)
			Expect(err).To(MatchError("invalid STK length: 0"))
		})
	})

	Context("source", func() {
		var (
			source *stkSource
			secret []byte
			ip4    net.IP
			ip6    net.IP
		)

		BeforeEach(func() {
			var err error

			ip4 = net.ParseIP("1.2.3.4")
			Expect(ip4).NotTo(BeEmpty())
			ip6 = net.ParseIP("2001:0db8:0000:0000:0000:ff00:0042:8329")
			Expect(ip6).NotTo(BeEmpty())

			secret = []byte("TESTING")
			sourceI, err := NewStkSource(secret)
			source = sourceI.(*stkSource)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate new tokens", func() {
			token, err := source.NewToken(ip4)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).ToNot(BeEmpty())
		})

		It("should generate and verify ipv4 tokens", func() {
			stk, err := source.NewToken(ip4)
			Expect(err).NotTo(HaveOccurred())
			Expect(stk).ToNot(BeEmpty())
			err = source.VerifyToken(ip4, stk)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate and verify ipv6 tokens", func() {
			stk, err := source.NewToken(ip6)
			Expect(err).NotTo(HaveOccurred())
			Expect(stk).ToNot(BeEmpty())
			err = source.VerifyToken(ip6, stk)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject empty tokens", func() {
			err := source.VerifyToken(ip4, nil)
			Expect(err).To(HaveOccurred())
		})

		It("should reject invalid tokens", func() {
			err := source.VerifyToken(ip4, []byte("foobar"))
			Expect(err).To(HaveOccurred())
		})

		It("should reject outdated tokens", func() {
			stk, err := encryptToken(source.aead, &sourceAddressToken{
				sourceAddr: ip4,
				timestamp:  uint64(time.Now().Unix() - protocol.STKExpiryTimeSec - 1),
			})
			Expect(err).NotTo(HaveOccurred())
			err = source.VerifyToken(ip4, stk)
			Expect(err).To(MatchError("STK expired"))
		})

		It("should reject tokens with wrong IP addresses", func() {
			otherIP := net.ParseIP("4.3.2.1")
			stk, err := encryptToken(source.aead, &sourceAddressToken{
				sourceAddr: otherIP,
				timestamp:  uint64(time.Now().Unix()),
			})
			Expect(err).NotTo(HaveOccurred())
			err = source.VerifyToken(ip4, stk)
			Expect(err).To(MatchError("invalid source address in STK"))
		})
	})
})
