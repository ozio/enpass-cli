package enpass

import (
	"testing"
	"time"
)

func TestComputeTOTP_RFC6238_SHA1_6Digits(t *testing.T) {
	// RFC 6238 Appendix B uses the ASCII secret "12345678901234567890"
	// which is base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ". The published
	// 8-digit codes truncated to 6 digits (mod 10^6) are the expected
	// 6-digit values for the same timestamps.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		got, err := ComputeTOTP(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("unix=%d: unexpected error: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("unix=%d: got %q, want %q", tc.unix, got, tc.want)
		}
	}
}

func TestComputeTOTP_OtpAuthURI(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6&algorithm=SHA1"
	got, err := ComputeTOTP(uri, time.Unix(1234567890, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "005924" {
		t.Errorf("got %q, want %q", got, "005924")
	}
}

func TestComputeTOTP_NormalizesSecret(t *testing.T) {
	// Spaces, dashes and missing padding should all parse.
	got, err := ComputeTOTP("gezd gnbv-gy3tqojq gezd gnbv-gy3tqojq", time.Unix(1234567890, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "005924" {
		t.Errorf("got %q, want %q", got, "005924")
	}
}

func TestComputeTOTP_RejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "!!!not-base32!!!", "otpauth://totp/foo"} {
		if _, err := ComputeTOTP(in, time.Unix(0, 0)); err == nil {
			t.Errorf("input %q: expected error, got nil", in)
		}
	}
}

func TestComputeTOTPRejectsMalformedParameters(t *testing.T) {
	for _, suffix := range []string{"digits=", "period=", "algorithm=", "digits=0", "digits=5", "digits=9", "digits=32", "digits=abc", "period=0", "period=-1", "period=abc", "algorithm=MD5", "secret=JBSWY3DPEHPK3PXP", "digits=6&digits=8"} {
		value := "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&" + suffix
		if _, err := ComputeTOTP(value, time.Unix(59, 0)); err == nil {
			t.Errorf("accepted %s", suffix)
		}
	}
	if _, err := ComputeTOTP("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP", time.Unix(59, 0)); err == nil {
		t.Fatal("HOTP accepted")
	}
}

func TestDecryptMalformedKeyDoesNotPanic(t *testing.T) {
	for _, size := range []int{0, 1, 31, 32, 43, 45} {
		c := Card{Type: "password", value: "00", itemKey: make([]byte, size)}
		if _, err := c.Decrypt(); err == nil {
			t.Errorf("accepted key size %d", size)
		}
	}
}
