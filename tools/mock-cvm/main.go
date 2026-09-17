// mock-cvm: generate a complete, internally consistent Azure confidential-VM
// evidence bundle for offline tests, using go-sev-guest's test-only AMD key
// hierarchy. Nothing here is a real attestation; the ARK is a test key and the
// Rust tests pin it only under cfg(test).
//
//	go run . -out ../../crates/adns-attest/tests/fixtures/mock-cvm
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	test "github.com/google/go-sev-guest/testing"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func pemBytes(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
func write(dir, name string, b []byte) { must(os.WriteFile(filepath.Join(dir, name), b, 0o644)) }

func main() {
	out := flag.String("out", "fixtures", "output directory")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))
	now := time.Date(2026, 9, 16, 17, 0, 0, 0, time.UTC)

	// ---- AMD side: Genoa test chain (ARK -> ASK -> VCEK) with hwid/TCB extensions
	hwid := sha512sum("mock-cvm hwid")
	tcb, err := kds.ComposeTCBParts(kds.TCBParts{BlSpl: 7, TeeSpl: 0, SnpSpl: 14, UcodeSpl: 72})
	must(err)
	parts := kds.TCBParts{BlSpl: 7, TeeSpl: 0, SnpSpl: 14, UcodeSpl: 72}
	b := &test.AmdSignerBuilder{Keys: test.DefaultAmdKeys(), ProductName: "Genoa", CSPID: "mock-cvm",
		ArkCreationTime: now, AskCreationTime: now, AsvkCreationTime: now, VcekCreationTime: now, VlekCreationTime: now, TCB: tcb,
		// the default fake VCEK carries zero hwid/TCB extensions; make them match the report
		VcekCustom: test.CertOverride{Extensions: amdExtensions(parts, hwid[:])}}
	copy(b.HWID[:], hwid[:])
	signer, err := b.TestOnlyCertChain()
	must(err)

	// ---- vTPM side: RSA-2048 AK, leaf cert issued by a test "Azure Cloud Virtual TPM CA - 25"
	caKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	akKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Azure Cloud Virtual TPM CA - 25"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	must(err)
	ca, _ := x509.ParseCertificate(caDER)
	akTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mockcvm0000.ConfidentialVM.Azure.windows.net"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}}}
	akDER, err := x509.CreateCertificate(rand.Reader, akTpl, ca, &akKey.PublicKey, caKey)
	must(err)

	// ---- runtime data (HCL claims JSON) carrying the AK public key; report_data = SHA-256(runtime) || 0^32
	n := akKey.PublicKey.N.Bytes()
	runtime, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{{"kid": "HCLAkPub", "key_ops": []string{"sign"}, "kty": "RSA",
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), "n": base64.RawURLEncoding.EncodeToString(n)}},
		"vm-configuration": map[string]any{"console-enabled": true, "secure-boot": true, "tpm-enabled": true, "vmUniqueId": "MOCK-CVM"},
	})
	rd := sha256.Sum256(runtime)

	// ---- SNP report v2: VCEK-signed, policy bit 17 only, VMPL 0, no debug/migration
	report := make([]byte, abi.ReportSize)
	le32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(report[off:], v) }
	le64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(report[off:], v) }
	le32(0x00, 2)                  // version
	le64(0x08, 1<<17)              // policy: reserved-must-be-one bit only
	le32(0x30, 0)                  // vmpl
	le32(0x34, 1)                  // signature algo: ECDSA P-384 / SHA-384
	le64(0x38, uint64(tcb))        // current tcb
	le32(0x48, 0)                  // flags: VCEK, unmasked chip id
	copy(report[0x50:0x70], rd[:]) // report_data[..32]; tail stays zero
	measurement := sha512sum("mock-cvm measurement")
	copy(report[0x90:0xC0], measurement[:48])
	hostData := sha256.Sum256([]byte("mock-cvm host_data"))
	copy(report[0xC0:0xE0], hostData[:])
	le64(0x180, uint64(tcb)) // reported tcb
	copy(report[0x1A0:0x1E0], hwid[:])
	le64(0x1E0, uint64(tcb)) // committed tcb
	le64(0x1F0, uint64(tcb)) // launch tcb
	r, s, err := signer.Sign(abi.SignedComponent(report))
	must(err)
	must(abi.SetSignature(r, s, report))

	// ---- HCL container exactly as the guest exposes it in TPM NV 0x1400001
	claims := uint32(len(runtime))
	size := 1236 + claims
	hcl := make([]byte, 2600)
	copy(hcl[0:], "HCLA")
	binary.LittleEndian.PutUint32(hcl[4:], 2)
	binary.LittleEndian.PutUint32(hcl[8:], size)
	binary.LittleEndian.PutUint32(hcl[12:], 2)
	copy(hcl[32:1216], report)
	binary.LittleEndian.PutUint32(hcl[1216:], 20+claims)
	binary.LittleEndian.PutUint32(hcl[1220:], 1)
	binary.LittleEndian.PutUint32(hcl[1224:], 2)
	binary.LittleEndian.PutUint32(hcl[1228:], 1)
	binary.LittleEndian.PutUint32(hcl[1232:], claims)
	copy(hcl[1236:], runtime)

	// ---- outputs
	write(*out, "hcl.bin", hcl)
	write(*out, "runtime.json", runtime)
	write(*out, "endorsements.pem", append(append(pemBytes("CERTIFICATE", signer.Vcek.Raw), pemBytes("CERTIFICATE", signer.Ask.Raw)...), pemBytes("CERTIFICATE", signer.Ark.Raw)...))
	write(*out, "ark_test.pem", pemBytes("CERTIFICATE", signer.Ark.Raw))
	write(*out, "ak_chain.pem", append(pemBytes("CERTIFICATE", akDER), pemBytes("CERTIFICATE", caDER)...))
	akPriv, _ := x509.MarshalPKCS8PrivateKey(akKey)
	write(*out, "ak_private_test.pem", pemBytes("PRIVATE KEY", akPriv))
	arkSum := sha256.Sum256(signer.Ark.Raw)
	rootSum := sha256.Sum256(caDER)
	manifest, _ := json.MarshalIndent(map[string]any{
		"security_claim": false, "generator": "tools/mock-cvm (go-sev-guest test keys)", "product": "Genoa",
		"tcb":         map[string]int{"boot_loader": 7, "tee": 0, "snp": 14, "microcode": 72},
		"chip_id_hex": hex.EncodeToString(hwid[:]), "measurement_hex": hex.EncodeToString(measurement[:48]),
		"host_data_hex": hex.EncodeToString(hostData[:]), "report_data_hex": hex.EncodeToString(rd[:]),
		"ark_cert_sha256": hex.EncodeToString(arkSum[:]), "ak_root_sha256": hex.EncodeToString(rootSum[:]),
		"ak_ca_subject": "Azure Cloud Virtual TPM CA - 25", "now_unix": now.Unix(),
	}, "", "  ")
	write(*out, "manifest.json", manifest)
}

func sha512sum(s string) [64]byte {
	h := sha512New()
	h.Write([]byte(s))
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// amdExtensions mirrors go-sev-guest's fake VCEK extensions but encodes hwID the
// way real AMD VCEKs do: the raw 64 bytes, not an ASN.1 OCTET STRING wrapper.
func amdExtensions(parts kds.TCBParts, hwid []byte) []pkix.Extension {
	exts := test.CustomExtensions(parts, hwid, "mock-cvm", "Genoa")
	for i := range exts {
		if exts[i].Id.String() == "1.3.6.1.4.1.3704.1.4" {
			exts[i].Value = hwid
		}
	}
	return exts
}
