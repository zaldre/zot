package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/opencontainers/go-digest"
)

const (
	httpTimeout        = 5 * time.Minute
	certsPath          = "/etc/containers/certs.d"
	homeCertsDir       = ".config/containers/certs.d"
	ClientCertFilename = "client.cert"
	ClientKeyFilename  = "client.key"
	CaCertFilename     = "ca.crt"

	CosignSignature   = "cosign"
	CosignSigKey      = "dev.cosignproject.cosign/signature"
	NotationSignature = "notation"
	// ArtifactTypeNotation is the same value as github.com/notaryproject/notation-go/registry.ArtifactTypeNotation
	// (assert by internal test).
	// reason used: to reduce zot minimal binary size (otherwise adds oras.land/oras-go/v2 deps).
	ArtifactTypeNotation     = "application/vnd.cncf.notary.signature"
	ArtifactTypeCosign       = "application/vnd.dev.cosign.artifact.sig.v1+json"
	ArtifactTypeCosignBundle = "application/vnd.dev.sigstore.bundle.v0.3+json"
	// CosignSignatureTagSuffix is the suffix used for cosign signature tags (e.g., "sha256-digest.sig").
	// Using constant to avoid pulling in cosign dependency.
	CosignSignatureTagSuffix = "sig"
)

var cosignSignatureTagRule = regexp.MustCompile(`sha256\-.+\.sig`)

var cosignSBOMTagRule = regexp.MustCompile(`sha256\-.+\.sbom`)

func IsCosignSignature(tag string) bool {
	return cosignSignatureTagRule.MatchString(tag)
}

func IsCosignSBOM(tag string) bool {
	return cosignSBOMTagRule.MatchString(tag)
}

func IsCosignTag(tag string) bool {
	return IsCosignSignature(tag) || IsCosignSBOM(tag)
}

// IsArtifactTypeCosign returns true if the given artifact type corresponds to a cosign signature,
// covering both the legacy type and the newer sigstore bundle type.
func IsArtifactTypeCosign(artifactType string) bool {
	return artifactType == ArtifactTypeCosign || artifactType == ArtifactTypeCosignBundle
}

// RemoveFrom removes matches of item in [].
func RemoveFrom(inputSlice []string, item string) []string {
	var newSlice []string

	for _, v := range inputSlice {
		if item != v {
			newSlice = append(newSlice, v)
		}
	}

	return newSlice
}

func TypeOf(v any) string {
	return fmt.Sprintf("%T", v)
}

func DirExists(d string) bool {
	if !utf8.ValidString(d) {
		return false
	}

	fileInfo, err := os.Stat(d) //nolint: gosec
	if err != nil {
		if e, ok := err.(*fs.PathError); ok && errors.Is(e.Err, syscall.ENAMETOOLONG) || //nolint: errorlint
			errors.Is(e.Err, syscall.EINVAL) {
			return false
		}
	}

	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fileInfo.IsDir() {
		return false
	}

	return true
}

// MarshalThroughStruct is used to filter a json fields by using an intermediate struct.
func MarshalThroughStruct(obj any, throughStruct any) ([]byte, error) {
	toJSON, err := json.Marshal(obj)
	if err != nil {
		return []byte{}, err
	}

	err = json.Unmarshal(toJSON, throughStruct)
	if err != nil {
		return []byte{}, err
	}

	toJSON, err = json.Marshal(throughStruct)
	if err != nil {
		return []byte{}, err
	}

	return toJSON, nil
}

func ContainsStringIgnoreCase(strSlice []string, str string) bool {
	return slices.ContainsFunc(strSlice, func(val string) bool {
		return strings.EqualFold(val, str)
	})
}

// referrersTagRule matches the referrers fallback tag schema exactly: the
// algorithm, a hyphen, and the full hex encoding of a digest. It is anchored at
// both ends deliberately. An unanchored rule also matches any tag that merely
// ENDS in something digest-shaped -- "v1-sha256-abcdef", "notsha256-abcdef" --
// and a permissive character class matches short suffixes like "sha256-zzz"
// that no digest can produce.
//
// Hex is lowercase only, matching go-digest's own `^[a-f0-9]{64}$` for sha256.
// An uppercase tag is a legal OCI tag that no digest encoding can equal, so it
// is ordinary content rather than a referrers entry.
var referrersTagRule = regexp.MustCompile(`^sha256-[a-f0-9]{64}$`)

// IsReferrersTag checks if tag has the referrers tag schema shape
// (https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema).
//
// Shape alone does not prove a tag IS a referrers entry -- see IsDigestNamedTag.
func IsReferrersTag(tag string) bool {
	return referrersTagRule.MatchString(tag)
}

// IsDigestNamedTag reports whether tag names the digest of the manifest it
// resolves to.
//
// Such a tag has the referrers fallback shape but is not a referrers entry. The
// referrers schema names the SUBJECT's digest, so the index it tags is by
// construction a different manifest than the one named. A tag that names its
// own target is instead an ordinary image tagged by digest, which is what
// mirroring tools write when the source was pinned by digest -- oc-mirror
// renders "repo@sha256:x" as "repo:sha256-x". Treating those as referrers hides
// real images from metadb, and therefore from the search extension and the UI,
// while leaving them fully served over the distribution API.
func IsDigestNamedTag(tag string, dgst digest.Digest) bool {
	// Parsed by hand rather than via Algorithm()/Encoded(), which panic on a digest
	// carrying no separator; callers reach here with whatever the store held.
	alg, hex, found := strings.Cut(dgst.String(), ":")

	return found && tag == alg+"-"+hex
}

// IsReferrersEntry reports whether a reference is a referrers fallback tag, and
// therefore a transport artifact rather than content in its own right.
//
// This is the discriminator shared by metadb and sync: referrers-shaped, and not
// naming its own target. Shape alone is not enough, because an image tagged by
// digest has exactly the same shape -- see IsDigestNamedTag.
func IsReferrersEntry(tag string, dgst digest.Digest) bool {
	return IsReferrersTag(tag) && !IsDigestNamedTag(tag, dgst)
}

func IsContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// GetLocalIPs gets a list of IP addresses configured on the host's
// interfaces.
func GetLocalIPs() ([]string, error) {
	var localIPs []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return localIPs, err
		}

		for _, addr := range addrs {
			if localIP, ok := addr.(*net.IPNet); ok {
				localIPs = append(localIPs, localIP.IP.String())
			}
		}
	}

	return localIPs, nil
}

// GetLocalSockets gets a list of listening sockets on the host (IP:port).
// IPv6 is returned as [host]:port.
func GetLocalSockets(port string) ([]string, error) {
	localIPs, err := GetLocalIPs()
	if err != nil {
		return []string{}, err
	}

	localSockets := make([]string, len(localIPs))

	for idx, ip := range localIPs {
		// JoinHostPort automatically wraps IPv6 addresses in []
		localSockets[idx] = net.JoinHostPort(ip, port)
	}

	return localSockets, nil
}

func GetIPFromHostName(host string) ([]string, error) {
	addrs, err := net.LookupIP(host) //nolint: noctx
	if err != nil {
		return []string{}, err
	}

	ips := make([]string, 0, len(addrs))

	for _, ip := range addrs {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// AreSocketsEqual checks if 2 sockets are equal at the host port level.
func AreSocketsEqual(socketA string, socketB string) (bool, error) {
	hostA, portA, err := net.SplitHostPort(socketA)
	if err != nil {
		return false, err
	}

	hostB, portB, err := net.SplitHostPort(socketB)
	if err != nil {
		return false, err
	}

	hostAIP := net.ParseIP(hostA)
	if hostAIP == nil {
		// this could be a fully-qualified domain name (FQDN)
		// for FQDN, just a normal compare is enough
		return hostA == hostB, nil
	}

	hostBIP := net.ParseIP(hostB)
	if hostBIP == nil {
		// if the host part of socketA was parsed successfully, it was an IP
		// if the host part of socketA was an FQDN, then the comparison is
		// already done as the host of socketB is also assumed to be an FQDN.
		// since the parsing failed, assume that A and B are not equal.
		return false, nil
	}

	return (hostAIP.Equal(hostBIP) && (portA == portB)), nil
}
