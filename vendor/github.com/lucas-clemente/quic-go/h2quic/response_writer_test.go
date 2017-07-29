package h2quic

import (
	"bytes"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStream struct {
	id           protocol.StreamID
	dataToRead   bytes.Buffer
	dataWritten  bytes.Buffer
	reset        bool
	closed       bool
	remoteClosed bool
}

func (s *mockStream) Close() error                          { s.closed = true; return nil }
func (s *mockStream) Reset(error)                           { s.reset = true }
func (s *mockStream) CloseRemote(offset protocol.ByteCount) { s.remoteClosed = true }
func (s mockStream) StreamID() protocol.StreamID            { return s.id }

func (s *mockStream) Read(p []byte) (int, error)  { return s.dataToRead.Read(p) }
func (s *mockStream) Write(p []byte) (int, error) { return s.dataWritten.Write(p) }

var _ = Describe("Response Writer", func() {
	var (
		w            *responseWriter
		headerStream *mockStream
		dataStream   *mockStream
	)

	BeforeEach(func() {
		headerStream = &mockStream{}
		dataStream = &mockStream{}
		w = newResponseWriter(headerStream, &sync.Mutex{}, dataStream, 5)
	})

	decodeHeaderFields := func() map[string][]string {
		fields := make(map[string][]string)
		decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
		h2framer := http2.NewFramer(nil, bytes.NewReader(headerStream.dataWritten.Bytes()))

		frame, err := h2framer.ReadFrame()
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&http2.HeadersFrame{}))
		hframe := frame.(*http2.HeadersFrame)
		mhframe := &http2.MetaHeadersFrame{HeadersFrame: hframe}
		Expect(mhframe.StreamID).To(BeEquivalentTo(5))
		mhframe.Fields, err = decoder.DecodeFull(hframe.HeaderBlockFragment())
		Expect(err).ToNot(HaveOccurred())
		for _, p := range mhframe.Fields {
			fields[p.Name] = append(fields[p.Name], p.Value)
		}
		return fields
	}

	It("writes status", func() {
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
	})

	It("writes headers", func() {
		w.Header().Add("content-length", "42")
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue("content-length", []string{"42"}))
	})

	It("writes multiple headers with the same name", func() {
		const cookie1 = "test1=1; Max-Age=7200; path=/"
		const cookie2 = "test2=2; Max-Age=7200; path=/"
		w.Header().Add("set-cookie", cookie1)
		w.Header().Add("set-cookie", cookie2)
		w.WriteHeader(http.StatusTeapot)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKey("set-cookie"))
		cookies := fields["set-cookie"]
		Expect(cookies).To(ContainElement(cookie1))
		Expect(cookies).To(ContainElement(cookie2))
	})

	It("writes data", func() {
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte("foobar")))
	})

	It("writes data after WriteHeader is called", func() {
		w.WriteHeader(http.StatusTeapot)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		fields := decodeHeaderFields()
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte("foobar")))
	})

	It("does not WriteHeader() twice", func() {
		w.WriteHeader(200)
		w.WriteHeader(500)
		fields := decodeHeaderFields()
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
	})

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		w.WriteHeader(304)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
		Expect(dataStream.dataWritten.Bytes()).To(HaveLen(0))
	})
})
