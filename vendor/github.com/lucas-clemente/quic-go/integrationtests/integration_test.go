package integrationtests

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"

	_ "github.com/lucas-clemente/quic-clients" // download clients

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("Integration tests", func() {
	BeforeEach(func() {
		dataMan.GenerateData(dataLen)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			It("gets a simple file", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host=127.0.0.1",
					"--port="+port,
					"https://quic.clemente.io/hello",
				)
				session, err := Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session).Should(Exit(0))
				Expect(session.Out).To(Say("Response:\nheaders: HTTP/1.1 200\nstatus: 200\n\nbody: Hello, World!\n"))
			})

			It("posts and reads a body", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host=127.0.0.1",
					"--port="+port,
					"--body=foo",
					"https://quic.clemente.io/echo",
				)
				session, err := Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session).Should(Exit(0))
				Expect(session.Out).To(Say("Response:\nheaders: HTTP/1.1 200\nstatus: 200\n\nbody: foo\n"))
			})

			It("gets a file", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host=127.0.0.1",
					"--port="+port,
					"https://quic.clemente.io/data",
				)
				session, err := Start(command, nil, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session, 2).Should(Exit(0))
				Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
			})

			It("gets many copies of a file in parallel", func() {
				wg := sync.WaitGroup{}
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer GinkgoRecover()
						command := exec.Command(
							clientPath,
							"--quic-version="+strconv.Itoa(int(version)),
							"--host=127.0.0.1",
							"--port="+port,
							"https://quic.clemente.io/data",
						)
						session, err := Start(command, nil, GinkgoWriter)
						Expect(err).NotTo(HaveOccurred())
						defer session.Kill()
						Eventually(session, 10).Should(Exit(0))
						Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
					}()
				}
				wg.Wait()
			})
		})
	}
})
