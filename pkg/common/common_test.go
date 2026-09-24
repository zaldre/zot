package common_test

import (
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
)

func TestCommon(t *testing.T) {
	Convey("test Contains()", t, func() {
		first := []string{"apple", "biscuit"}
		So(slices.Contains(first, "apple"), ShouldBeTrue)
		So(slices.Contains(first, "peach"), ShouldBeFalse)
		So(slices.Contains([]string{}, "apple"), ShouldBeFalse)
	})

	Convey("test MarshalThroughStruct()", t, func() {
		cfg := config.New()

		newCfg := struct {
			DistSpecVersion string
		}{}

		_, err := common.MarshalThroughStruct(cfg, &newCfg)
		So(err, ShouldBeNil)
		So(newCfg.DistSpecVersion, ShouldEqual, cfg.DistSpecVersion)

		// negative
		obj := make(chan int)
		toObj := config.New()

		_, err = common.MarshalThroughStruct(obj, &toObj)
		So(err, ShouldNotBeNil)

		_, err = common.MarshalThroughStruct(toObj, &obj)
		So(err, ShouldNotBeNil)
	})

	Convey("test dirExists()", t, func() {
		exists := common.DirExists("testdir")
		So(exists, ShouldBeFalse)

		tempDir := t.TempDir()

		file, err := os.Create(path.Join(tempDir, "file.txt"))
		So(err, ShouldBeNil)

		isDir := common.DirExists(file.Name())
		So(isDir, ShouldBeFalse)
	})

	Convey("Test ArtifactTypeNotation const has same value as in notaryproject", t, func() {
		So(common.ArtifactTypeNotation, ShouldEqual, notreg.ArtifactTypeNotation)
	})

	Convey("Test IsArtifactTypeCosign", t, func() {
		So(common.IsArtifactTypeCosign(common.ArtifactTypeCosign), ShouldBeTrue)
		So(common.IsArtifactTypeCosign(common.ArtifactTypeCosignBundle), ShouldBeTrue)
		So(common.IsArtifactTypeCosign(common.ArtifactTypeNotation), ShouldBeFalse)
		So(common.IsArtifactTypeCosign("application/example"), ShouldBeFalse)
	})

	Convey("Test GetLocalIPs", t, func() {
		localIPs, err := common.GetLocalIPs()
		So(err, ShouldBeNil)
		So(localIPs, ShouldNotBeEmpty)
		So(localIPs, ShouldContain, "127.0.0.1")
	})

	Convey("Test GetLocalSockets IPv4", t, func() {
		localSockets, err := common.GetLocalSockets("8765")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "127.0.0.1:8765")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8765")
		}
	})

	Convey("Test GetLocalSockets IPv6", t, func() {
		localSockets, err := common.GetLocalSockets("8766")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "[::1]:8766")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8766")
		}
	})

	Convey("Test GetIPFromHostName with valid hostname", t, func() {
		addrs, err := common.GetIPFromHostName("github.com")

		// we can't check the actual addresses here as they can change
		So(err, ShouldBeNil)
		So(addrs, ShouldNotBeEmpty)
	})

	Convey("Test GetIPFromHostName with non-existent hostname", t, func() {
		addrs, err := common.GetIPFromHostName("thisdoesnotexist")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "lookup thisdoesnotexist")
		So(addrs, ShouldBeEmpty)
	})

	Convey("Test AreSocketsEqual with equal IPv4 sockets", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with equal IPv6 sockets", t, func() {
		result, err := common.AreSocketsEqual("[::1]:9000", "[0000:0000:0000:0000:0000:0000:0000:0001]:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket ports", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9001")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket hosts", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.2:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with 2 equal host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with 2 different host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "notlocalhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with hostname and IP address", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with IP address and hostname", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid first socket", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1", "localhost:9000")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid second socket", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})
}

func TestReferrersTagDiscrimination(t *testing.T) {
	const (
		hex   = "4a62254e90931470fb90c29362803fe7dada22107229ec2351bd33560c1dceb0"
		other = "2d1acb6e828945aeadeee396baea355e3fb81101809ef836bc30892a4f284dfe"
	)

	Convey("only the exact referrers schema is a referrers tag", t, func() {
		// Shapes that merely contain or resemble a digest are ordinary tags.
		So(common.IsReferrersTag("1.0.0"), ShouldBeFalse)
		So(common.IsReferrersTag("abc-123"), ShouldBeFalse)
		So(common.IsReferrersTag("sha256"+hex), ShouldBeFalse)          // no separator
		So(common.IsReferrersTag("sha256-abc123def456"), ShouldBeFalse) // too short
		So(common.IsReferrersTag("sha256-zzz"), ShouldBeFalse)          // not hex
		So(common.IsReferrersTag("notsha256-"+hex), ShouldBeFalse)      // unanchored head
		So(common.IsReferrersTag("v1-sha256-"+hex), ShouldBeFalse)      // unanchored head
		So(common.IsReferrersTag("sha256-"+hex+".sig"), ShouldBeFalse)  // cosign, has a tail

		// go-digest encodes sha256 as `^[a-f0-9]{64}$`, so an uppercase tag is a legal
		// OCI tag that no digest can equal -- ordinary content, not a referrers entry.
		So(common.IsReferrersTag("sha256-"+strings.ToUpper(hex)), ShouldBeFalse)

		So(common.IsReferrersTag("sha256-"+hex), ShouldBeTrue)
	})

	Convey("a digest-named tag is an image, not a referrers entry", t, func() {
		// oc-mirror renders repo@sha256:x as repo:sha256-x, so the tag names the
		// digest of the manifest it resolves to. A referrers tag names the
		// SUBJECT's digest and therefore never matches its own target.
		So(common.IsDigestNamedTag("sha256-"+hex, godigest.Digest("sha256:"+hex)), ShouldBeTrue)
		So(common.IsDigestNamedTag("sha256-"+hex, godigest.Digest("sha256:"+other)), ShouldBeFalse)

		So(common.IsDigestNamedTag("1.0.0", godigest.Digest("sha256:"+hex)), ShouldBeFalse)
		So(common.IsDigestNamedTag("sha256-"+hex, godigest.Digest("nocolon")), ShouldBeFalse)
		So(common.IsDigestNamedTag("", godigest.Digest("")), ShouldBeFalse)
	})

	Convey("IsReferrersEntry requires the shape and a digest it does not name", t, func() {
		// The shared discriminator: only a referrers-shaped tag pointing at some OTHER
		// manifest is a referrers entry. metadb skips exactly these, and sync declines
		// to copy them as images.
		So(common.IsReferrersEntry("sha256-"+hex, godigest.Digest("sha256:"+other)), ShouldBeTrue)

		// Self-naming -- an image tagged by digest, not a referrers entry.
		So(common.IsReferrersEntry("sha256-"+hex, godigest.Digest("sha256:"+hex)), ShouldBeFalse)

		// Wrong shape, whatever the digest.
		So(common.IsReferrersEntry("1.0.0", godigest.Digest("sha256:"+other)), ShouldBeFalse)
		So(common.IsReferrersEntry("v1-sha256-"+hex, godigest.Digest("sha256:"+other)), ShouldBeFalse)
		So(common.IsReferrersEntry("sha256-"+hex+".sig", godigest.Digest("sha256:"+other)), ShouldBeFalse)

		// A digest reference rather than a tag: the separator is a colon, not a hyphen.
		So(common.IsReferrersEntry("sha256:"+hex, godigest.Digest("sha256:"+hex)), ShouldBeFalse)

		// A digest carrying no separator must not panic the way Algorithm() would.
		So(common.IsReferrersEntry("sha256-"+hex, godigest.Digest("nosep")), ShouldBeTrue)
		So(common.IsDigestNamedTag("sha256-"+hex, godigest.Digest("")), ShouldBeFalse)
	})
}
