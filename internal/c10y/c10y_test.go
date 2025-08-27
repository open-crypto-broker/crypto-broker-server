package c10y

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"reflect"
	"testing"
)

var bb = []byte(`ɥsɐɥ oʇ sɹǝʇɔɐɹɐɥɔ ʎɹɐɹʇᴉqɹɐ ǝɯoS
╔════╦══════╦══╗
╠═══╗║╠═══╦╗║╚╗║
║╔═╗╬╠═╦═╣║║╚╚║║
║╚╗╠╚╦║║╔═╣╚═╦╝║
║║║╝╔═╩╝║╠╝╣╔╝╔╣
║║╚═╣╔══╣╔═╝║╩╣║
║╚═╗╚╝╣║╝║╝═╩╔╩║
╚══╩══╩══╩═════╝`)

// BenchmarkLibraryNative_HashSHA3_256 to run benchmark:
// go test -benchmem -run=^$ -bench ^BenchmarkLibraryNative_HashSHA3_256$ github.com/open-crypto-broker/crypto-broker-server/internal/c10y
func BenchmarkLibraryNative_HashSHA3_256(b *testing.B) {
	service := NewLibraryNative()
	for i := 0; i < b.N; i++ {
		service.HashSHA3_256(bb)
	}
}

func TestParseX509Cert(t *testing.T) {
	type args struct {
		rawCert []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ParseX509Cert reutrns error given empty rawCert bytes",
			args: args{
				rawCert: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "ParseX509Cert returns error given RSA priv key bytes #1",
			args: args{
				rawCert: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxM8/6O8EqHjFWPV6sWeauYM+xNUrvZWuFjc/RLyhWE9WXAD/
uqHg67P8zkfg1Nxk/A87FDI4vsULt9SbSnjZCbG9fI3BdqogWWXSxpvsiS1Hp5r7
7mtIgTIOYe/ReS4/Rn2VVj8w9SKbXgkzSpQhjScP2J2MnguDErpc7DT1L6uBadfp
c2E4QzX1/bTu4E18af/zcBVJ4KAj+MnaQrZH76Qrnx5q6NqyCN1VTUm0ZVm13VuI
xNDY8qozyoPxddbs9mX4HRpgz99d6Ere+E95XT8Kahu2h3FJPkiWUDmi3kYh7OSx
200OA8ybLXxJGdIzYGe3gcnVAtPbXjPUOWx5rQIDAQABAoIBAA7xlNVRMmK/naFH
xzb2bYdahNPM3KzHhosFsa/v1rYHro0yPwV8lyeugfdm+i/13O3neVseORrOVKAM
hg7dWc8XoavccG0ozwE0VXdiwLVMLKp4S44ETWJ2wSRq+wlr6CTbeKrIBfKgqKvQ
oDljqAYf8JJIQprmUUYekNtKmVD/xW8xbC9x0tfTLcZ3azsQWGBQgVN0DKo2hDtm
9wh6yDO6E1TxNqcsoSyKJBF/G1xZFr2oPVkYiyzffDkuXc4SwIG/Cew4Tf5sRvfe
lGNvxE3QYiF7X3Jq1qgXRd1jVDFOLWhzXy6cEpmbM1mC3M3KFUhqGcKgXqlpAqMW
osZTNO0CgYEA/XYlvzxgWog/n/QedzOvWaUHxyOXkIwdJxM54rA9SGLQGY8nsOvt
XIn8F3wDVjITMQyVG3R9OwLGVTEI22nCqdiDP20IgJPjZO41Nh16cxsPM/3QGe2Q
ual8UVfAoqLZuNZRSYRnM26S4Ivm9uCjtFEspNb+zO+KSP6aj2d+3FMCgYEAxsfa
CSnIFklMfvb0aT6xCNvTzKeUpujejrS7JelSNGDesjBTTpT+b9jnCKRipkBMe1o5
/hU+G/yIOx/38YzWbSxLAccTFty5q72EHnpAdwl4M+pkRy65MQI0SG9SKTi9Vna0
7WhgQuNz2o1YIHFQVUK6WU4Cvec0qYIdTdMskf8CgYEAkX9iGc5Z7X5rL7IeTwU/
crF2ro0y80pLbePuhb/v3f7DQPjZqwk0H7wiF4UcET37oFt9uN39CYQFQGA+ml2y
3ncomJ9Jky3SCl1n9GGlqi/tYUYhUND8FGhDshoyvenIHAADd7Vm3LJr5DTLaAr6
ToeOni3A5PnZIx/sr8eUnnsCgYEAjDPJhU0C4zUvzx0/pjuhgi4KZP6NymvVDbJL
jaHTaT4p1GRhXbuY+ipySZYoPjp7t0UcQimZdQPY0lrp9mTvmHD1NnvC6w0jqA4z
cYuojE0Riwx3Tf2WgQqc9boOqSRr5uAzHH/R5VuoCy5GShuiHYDDDtoG9QpuCmDL
amjXtuECgYEAxkdsOAtmCihgDucHTht1zNImBNB/31+iZ1R3q78PkUwLWC5GGU/x
3nMsr2pvQgb1cC9Wdi8vAHz4bxDsPNzKJ1Tlyrxp1o4J8sJM64n3gY+HaGk3HRbQ
kLCBYOHSXIZVDr/GFND1zYDbMky/HNWFo0RxhEZL7ihtvugnHhGuOno=
-----END RSA PRIVATE KEY-----
`),
			},
			wantErr: true,
		},
		{
			name: "ParseX509Cert succeeds given valid certificate bytes",
			args: args{
				rawCert: []byte(`-----BEGIN CERTIFICATE-----
MIICjTCCAjMCFFZylIOCFbBNCArZuYH9Am7mx/HgMAoGCCqGSM49BAMCMDQxCzAJ
BgNVBAYTAkRFMRMwEQYDVQQKDApNeSBUZXN0IENBMRAwDgYDVQQDDAdUZXN0IENB
MB4XDTI1MDYyNzA3NTY0OVoXDTM1MDYyNTA3NTY0OVowgZIxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQLDAlBY2NlbnR1cmUxKjAoBgkq
hkiG9w0BCQEWG2RhbmllbC5iZWNrZXJAYWNjZW50dXJlLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMTPP+jvBKh4xVj1erFnmrmDPsTVK72VrhY3
P0S8oVhPVlwA/7qh4Ouz/M5H4NTcZPwPOxQyOL7FC7fUm0p42QmxvXyNwXaqIFll
0sab7IktR6ea++5rSIEyDmHv0XkuP0Z9lVY/MPUim14JM0qUIY0nD9idjJ4LgxK6
XOw09S+rgWnX6XNhOEM19f207uBNfGn/83AVSeCgI/jJ2kK2R++kK58eaujasgjd
VU1JtGVZtd1biMTQ2PKqM8qD8XXW7PZl+B0aYM/fXehK3vhPeV0/CmobtodxST5I
llA5ot5GIezksdtNDgPMmy18SRnSM2Bnt4HJ1QLT214z1Dlsea0CAwEAATAKBggq
hkjOPQQDAgNIADBFAiEAm5qRf3sYRW6v44M4aEvQ6LNFODegDslLB8di10QHlYEC
IFJg2YEcgTg/KojYGjPBFjR0hlVnCuRYSHr6R7DLtv9J
-----END CERTIFICATE-----`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseX509Cert(tt.args.rawCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseX509Cert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestParsePrivateKeyFromPEM(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name    string
		args    args
		want    any
		wantErr bool
	}{
		{
			name: "ParsePrivateKeyFromPEM() returns error given empty key",
			args: args{
				key: []byte(``),
			},
			wantErr: true,
		},
		{
			name: "ParsePrivateKeyFromPEM() succeeds parsing RSA private key #1",
			args: args{
				key: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxM8/6O8EqHjFWPV6sWeauYM+xNUrvZWuFjc/RLyhWE9WXAD/
uqHg67P8zkfg1Nxk/A87FDI4vsULt9SbSnjZCbG9fI3BdqogWWXSxpvsiS1Hp5r7
7mtIgTIOYe/ReS4/Rn2VVj8w9SKbXgkzSpQhjScP2J2MnguDErpc7DT1L6uBadfp
c2E4QzX1/bTu4E18af/zcBVJ4KAj+MnaQrZH76Qrnx5q6NqyCN1VTUm0ZVm13VuI
xNDY8qozyoPxddbs9mX4HRpgz99d6Ere+E95XT8Kahu2h3FJPkiWUDmi3kYh7OSx
200OA8ybLXxJGdIzYGe3gcnVAtPbXjPUOWx5rQIDAQABAoIBAA7xlNVRMmK/naFH
xzb2bYdahNPM3KzHhosFsa/v1rYHro0yPwV8lyeugfdm+i/13O3neVseORrOVKAM
hg7dWc8XoavccG0ozwE0VXdiwLVMLKp4S44ETWJ2wSRq+wlr6CTbeKrIBfKgqKvQ
oDljqAYf8JJIQprmUUYekNtKmVD/xW8xbC9x0tfTLcZ3azsQWGBQgVN0DKo2hDtm
9wh6yDO6E1TxNqcsoSyKJBF/G1xZFr2oPVkYiyzffDkuXc4SwIG/Cew4Tf5sRvfe
lGNvxE3QYiF7X3Jq1qgXRd1jVDFOLWhzXy6cEpmbM1mC3M3KFUhqGcKgXqlpAqMW
osZTNO0CgYEA/XYlvzxgWog/n/QedzOvWaUHxyOXkIwdJxM54rA9SGLQGY8nsOvt
XIn8F3wDVjITMQyVG3R9OwLGVTEI22nCqdiDP20IgJPjZO41Nh16cxsPM/3QGe2Q
ual8UVfAoqLZuNZRSYRnM26S4Ivm9uCjtFEspNb+zO+KSP6aj2d+3FMCgYEAxsfa
CSnIFklMfvb0aT6xCNvTzKeUpujejrS7JelSNGDesjBTTpT+b9jnCKRipkBMe1o5
/hU+G/yIOx/38YzWbSxLAccTFty5q72EHnpAdwl4M+pkRy65MQI0SG9SKTi9Vna0
7WhgQuNz2o1YIHFQVUK6WU4Cvec0qYIdTdMskf8CgYEAkX9iGc5Z7X5rL7IeTwU/
crF2ro0y80pLbePuhb/v3f7DQPjZqwk0H7wiF4UcET37oFt9uN39CYQFQGA+ml2y
3ncomJ9Jky3SCl1n9GGlqi/tYUYhUND8FGhDshoyvenIHAADd7Vm3LJr5DTLaAr6
ToeOni3A5PnZIx/sr8eUnnsCgYEAjDPJhU0C4zUvzx0/pjuhgi4KZP6NymvVDbJL
jaHTaT4p1GRhXbuY+ipySZYoPjp7t0UcQimZdQPY0lrp9mTvmHD1NnvC6w0jqA4z
cYuojE0Riwx3Tf2WgQqc9boOqSRr5uAzHH/R5VuoCy5GShuiHYDDDtoG9QpuCmDL
amjXtuECgYEAxkdsOAtmCihgDucHTht1zNImBNB/31+iZ1R3q78PkUwLWC5GGU/x
3nMsr2pvQgb1cC9Wdi8vAHz4bxDsPNzKJ1Tlyrxp1o4J8sJM64n3gY+HaGk3HRbQ
kLCBYOHSXIZVDr/GFND1zYDbMky/HNWFo0RxhEZL7ihtvugnHhGuOno=
-----END RSA PRIVATE KEY-----
`),
			},
			wantErr: false,
		},
		{
			name: "ParsePrivateKeyFromPEM() succeeds parsing RSA private key #2",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDEzz/o7wSoeMVY
9XqxZ5q5gz7E1Su9la4WNz9EvKFYT1ZcAP+6oeDrs/zOR+DU3GT8DzsUMji+xQu3
1JtKeNkJsb18jcF2qiBZZdLGm+yJLUenmvvua0iBMg5h79F5Lj9GfZVWPzD1Ipte
CTNKlCGNJw/YnYyeC4MSulzsNPUvq4Fp1+lzYThDNfX9tO7gTXxp//NwFUngoCP4
ydpCtkfvpCufHmro2rII3VVNSbRlWbXdW4jE0NjyqjPKg/F11uz2ZfgdGmDP313o
St74T3ldPwpqG7aHcUk+SJZQOaLeRiHs5LHbTQ4DzJstfEkZ0jNgZ7eBydUC09te
M9Q5bHmtAgMBAAECggEADvGU1VEyYr+doUfHNvZth1qE08zcrMeGiwWxr+/Wtgeu
jTI/BXyXJ66B92b6L/Xc7ed5Wx45Gs5UoAyGDt1Zzxehq9xwbSjPATRVd2LAtUws
qnhLjgRNYnbBJGr7CWvoJNt4qsgF8qCoq9CgOWOoBh/wkkhCmuZRRh6Q20qZUP/F
bzFsL3HS19MtxndrOxBYYFCBU3QMqjaEO2b3CHrIM7oTVPE2pyyhLIokEX8bXFkW
vag9WRiLLN98OS5dzhLAgb8J7DhN/mxG996UY2/ETdBiIXtfcmrWqBdF3WNUMU4t
aHNfLpwSmZszWYLczcoVSGoZwqBeqWkCoxaixlM07QKBgQD9diW/PGBaiD+f9B53
M69ZpQfHI5eQjB0nEznisD1IYtAZjyew6+1cifwXfANWMhMxDJUbdH07AsZVMQjb
acKp2IM/bQiAk+Nk7jU2HXpzGw8z/dAZ7ZC5qXxRV8Ciotm41lFJhGczbpLgi+b2
4KO0USyk1v7M74pI/pqPZ37cUwKBgQDGx9oJKcgWSUx+9vRpPrEI29PMp5Sm6N6O
tLsl6VI0YN6yMFNOlP5v2OcIpGKmQEx7Wjn+FT4b/Ig7H/fxjNZtLEsBxxMW3Lmr
vYQeekB3CXgz6mRHLrkxAjRIb1IpOL1WdrTtaGBC43PajVggcVBVQrpZTgK95zSp
gh1N0yyR/wKBgQCRf2IZzlntfmsvsh5PBT9ysXaujTLzSktt4+6Fv+/d/sNA+Nmr
CTQfvCIXhRwRPfugW3243f0JhAVAYD6aXbLedyiYn0mTLdIKXWf0YaWqL+1hRiFQ
0PwUaEOyGjK96cgcAAN3tWbcsmvkNMtoCvpOh46eLcDk+dkjH+yvx5SeewKBgQCM
M8mFTQLjNS/PHT+mO6GCLgpk/o3Ka9UNskuNodNpPinUZGFdu5j6KnJJlig+Onu3
RRxCKZl1A9jSWun2ZO+YcPU2e8LrDSOoDjNxi6iMTRGLDHdN/ZaBCpz1ug6pJGvm
4DMcf9HlW6gLLkZKG6IdgMMO2gb1Cm4KYMtqaNe24QKBgQDGR2w4C2YKKGAO5wdO
G3XM0iYE0H/fX6JnVHervw+RTAtYLkYZT/Hecyyvam9CBvVwL1Z2Ly8AfPhvEOw8
3MonVOXKvGnWjgnywkzrifeBj4doaTcdFtCQsIFg4dJchlUOv8YU0PXNgNsyTL8c
1YWjRHGERkvuKG2+6CceEa46eg==
-----END PRIVATE KEY-----
`),
			},
			wantErr: false,
		},
		{
			name: "ParsePrivateKeyFromPEM() succeeds parsing ECDSA private key #1",
			args: args{
				key: []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIATr1Zip8CZ8m/hZmFahJjCEH71D4PYOCIcdgGFj4r3kew63cdUkEP
OLPP8bep2mSshTFXN2jcOnVgOK/3Rt5VDwygBwYFK4EEACOhgYkDgYYABAEXt2jB
rMa0SBIcMLbyTV+eSzXk+yjYPUD97cErPoG57R805HYkIrOQZEc87mHtgB2Ms9T6
TtHRm7APUuXqMOKy2wC5zx59trptpJTnG32vTVMI9nz5EcVsGqDj/iuexHw76yLA
quZXsCfrbHwj7HTP6U41CCcDyEDqaln8kLyK1q8r+g==
-----END EC PRIVATE KEY-----
`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKeyFromPEM(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeyFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestMapStringToKeyUsage(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name    string
		args    args
		want    x509.KeyUsage
		wantErr bool
	}{
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDigitalSignature to x509.KeyUsageDigitalSignature",
			args: args{
				in: KeyUsageDigitalSignature,
			},
			want:    x509.KeyUsageDigitalSignature,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageContentCommitment to x509.KeyUsageContentCommitment",
			args: args{
				in: KeyUsageContentCommitment,
			},
			want:    x509.KeyUsageContentCommitment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageCRLSign to x509.KeyUsageCRLSign",
			args: args{
				in: KeyUsageCRLSign,
			},
			want:    x509.KeyUsageCRLSign,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyCertSign to x509.KeyUsageKeyCertSign",
			args: args{
				in: KeyUsageKeyCertSign,
			},
			want:    x509.KeyUsageCertSign,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDataEncipherment to x509.KeyUsageDataEncipherment",
			args: args{
				in: KeyUsageDataEncipherment,
			},
			want:    x509.KeyUsageDataEncipherment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDecipherOnly to x509.KeyUsageDecipherOnly",
			args: args{
				in: KeyUsageDecipherOnly,
			},
			want:    x509.KeyUsageDecipherOnly,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageEncipherOnly to x509.KeyUsageEncipherOnly",
			args: args{
				in: KeyUsageEncipherOnly,
			},
			want:    x509.KeyUsageEncipherOnly,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyAgreement to x509.KeyUsageKeyAgreement",
			args: args{
				in: KeyUsageKeyAgreement,
			},
			want:    x509.KeyUsageKeyAgreement,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyEncipherment to x509.KeyUsageKeyEncipherment",
			args: args{
				in: KeyUsageKeyEncipherment,
			},
			want:    x509.KeyUsageKeyEncipherment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() fails to map unknown phrase",
			args: args{
				in: "abc",
			},
			want:    x509.KeyUsage(0),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapStringToKeyUsage(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapStringToKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapStringToKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapExtKeyUsage(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name    string
		args    args
		want    x509.ExtKeyUsage
		wantErr bool
	}{
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageServerAuth to x509.ExtKeyUsageServerAuth",
			args: args{
				in: ExtKeyUsageServerAuth,
			},
			want:    x509.ExtKeyUsageServerAuth,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageClientAuth to x509.ExtKeyUsageClientAuth",
			args: args{
				in: ExtKeyUsageClientAuth,
			},
			want:    x509.ExtKeyUsageClientAuth,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageCodeSigning to x509.ExtKeyUsageCodeSigning",
			args: args{
				in: ExtKeyUsageCodeSigning,
			},
			want:    x509.ExtKeyUsageCodeSigning,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageEmailProtection to x509.ExtKeyUsageEmailProtection",
			args: args{
				in: ExtKeyUsageEmailProtection,
			},
			want:    x509.ExtKeyUsageEmailProtection,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageTimeStamping to x509.ExtKeyUsageTimeStamping",
			args: args{
				in: ExtKeyUsageTimeStamping,
			},
			want:    x509.ExtKeyUsageTimeStamping,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageOCSPSigning to x509.ExtKeyUsageOCSPSigning",
			args: args{
				in: ExtKeyUsageOCSPSigning,
			},
			want:    x509.ExtKeyUsageOCSPSigning,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() fails to map unknown phrase",
			args: args{
				in: "abc",
			},
			want:    x509.ExtKeyUsage(0),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapExtKeyUsage(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapExtKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapExtKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComposeSignatureAlgorithm(t *testing.T) {
	type args struct {
		signAlg Algorithm
		hashAlg Algorithm
	}
	tests := []struct {
		name    string
		args    args
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA256 given signAlg: ECDSA, hashAlg: SHA_256",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_256,
			},
			want:    x509.ECDSAWithSHA256,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA384 given signAlg: ECDSA, hashAlg: SHA_384",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_384,
			},
			want:    x509.ECDSAWithSHA384,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA512 given signAlg: ECDSA, hashAlg: SHA_512",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_512,
			},
			want:    x509.ECDSAWithSHA512,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported hashing algorithm with ECDSA",
			args: args{
				signAlg: ECDSA,
				hashAlg: RSA,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA256WithRSA given signAlg: RSA, hashAlg: SHA_256",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_256,
			},
			want:    x509.SHA256WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA384WithRSA given signAlg: RSA, hashAlg: SHA_384",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_384,
			},
			want:    x509.SHA384WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA512WithRSA given signAlg: RSA, hashAlg: SHA_512",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_512,
			},
			want:    x509.SHA512WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported hashing algorithm with RSA",
			args: args{
				signAlg: RSA,
				hashAlg: ECDSA,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported pair of algorithms",
			args: args{
				signAlg: SHA3_512,
				hashAlg: ECDSA,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComposeSignatureAlgorithm(tt.args.signAlg, tt.args.hashAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComposeSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ComposeSignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePublicKey(t *testing.T) {
	csr := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIC2DCCAcACAQAwgZIxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzAN
BgNVBAcMBkJlcmxpbjEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk
MRIwEAYDVQQLDAlBY2NlbnR1cmUxKjAoBgkqhkiG9w0BCQEWG2RhbmllbC5iZWNr
ZXJAYWNjZW50dXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMTPP+jvBKh4xVj1erFnmrmDPsTVK72VrhY3P0S8oVhPVlwA/7qh4Ouz/M5H4NTc
ZPwPOxQyOL7FC7fUm0p42QmxvXyNwXaqIFll0sab7IktR6ea++5rSIEyDmHv0Xku
P0Z9lVY/MPUim14JM0qUIY0nD9idjJ4LgxK6XOw09S+rgWnX6XNhOEM19f207uBN
fGn/83AVSeCgI/jJ2kK2R++kK58eaujasgjdVU1JtGVZtd1biMTQ2PKqM8qD8XXW
7PZl+B0aYM/fXehK3vhPeV0/CmobtodxST5IllA5ot5GIezksdtNDgPMmy18SRnS
M2Bnt4HJ1QLT214z1Dlsea0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBKTYgW
LO8NA++5HRaCzeokHNw4ZffvN7v4ThaXY5m5pit0miROSEDscREaOqXlG1DZoF7r
sxx7UYL0CM4KGnTr8D3zOCykoNH8t73nWIKyUouPX7nbTve0udSwtJzbjkAqIsfu
/bQqDevPFLYVCv0AxfKiL6N4yiGUCY/rOtJnhXksyHRZrJO0Lf07LQaNMKlbHXeb
giZOJd5zqkWcdIhngALBmuua+8hlriv0778AwRGa1afK14/w88mNAPY948KXwj75
bWcqqXICM6paRxVqB6dUfFNzqSzDRRGj5dQbe24x88Jjv5E1SKRwv4Lb0q1JgfC1
AcGJkRMFqt3M96ox
-----END CERTIFICATE REQUEST-----`)
	block, _ := pem.Decode(csr)
	if block == nil {
		t.Error("could not decode CSR as PEM file")

		return
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Errorf("could not parse CSR, err: %s", err)

		return
	}

	type args struct {
		pubKey           any
		constraintsByAlg map[Algorithm]BitSizeConstraints
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidatePublicKey() returns no error if public key match constraints",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ValidatePublicKey() returns error if public key doesn't match constraints",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 4096,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ValidatePublicKey() returns error if missing constraints for that algorithm",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					ECDSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePublicKey(tt.args.pubKey, tt.args.constraintsByAlg); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePrivateKey(t *testing.T) {
	pk := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxM8/6O8EqHjFWPV6sWeauYM+xNUrvZWuFjc/RLyhWE9WXAD/
uqHg67P8zkfg1Nxk/A87FDI4vsULt9SbSnjZCbG9fI3BdqogWWXSxpvsiS1Hp5r7
7mtIgTIOYe/ReS4/Rn2VVj8w9SKbXgkzSpQhjScP2J2MnguDErpc7DT1L6uBadfp
c2E4QzX1/bTu4E18af/zcBVJ4KAj+MnaQrZH76Qrnx5q6NqyCN1VTUm0ZVm13VuI
xNDY8qozyoPxddbs9mX4HRpgz99d6Ere+E95XT8Kahu2h3FJPkiWUDmi3kYh7OSx
200OA8ybLXxJGdIzYGe3gcnVAtPbXjPUOWx5rQIDAQABAoIBAA7xlNVRMmK/naFH
xzb2bYdahNPM3KzHhosFsa/v1rYHro0yPwV8lyeugfdm+i/13O3neVseORrOVKAM
hg7dWc8XoavccG0ozwE0VXdiwLVMLKp4S44ETWJ2wSRq+wlr6CTbeKrIBfKgqKvQ
oDljqAYf8JJIQprmUUYekNtKmVD/xW8xbC9x0tfTLcZ3azsQWGBQgVN0DKo2hDtm
9wh6yDO6E1TxNqcsoSyKJBF/G1xZFr2oPVkYiyzffDkuXc4SwIG/Cew4Tf5sRvfe
lGNvxE3QYiF7X3Jq1qgXRd1jVDFOLWhzXy6cEpmbM1mC3M3KFUhqGcKgXqlpAqMW
osZTNO0CgYEA/XYlvzxgWog/n/QedzOvWaUHxyOXkIwdJxM54rA9SGLQGY8nsOvt
XIn8F3wDVjITMQyVG3R9OwLGVTEI22nCqdiDP20IgJPjZO41Nh16cxsPM/3QGe2Q
ual8UVfAoqLZuNZRSYRnM26S4Ivm9uCjtFEspNb+zO+KSP6aj2d+3FMCgYEAxsfa
CSnIFklMfvb0aT6xCNvTzKeUpujejrS7JelSNGDesjBTTpT+b9jnCKRipkBMe1o5
/hU+G/yIOx/38YzWbSxLAccTFty5q72EHnpAdwl4M+pkRy65MQI0SG9SKTi9Vna0
7WhgQuNz2o1YIHFQVUK6WU4Cvec0qYIdTdMskf8CgYEAkX9iGc5Z7X5rL7IeTwU/
crF2ro0y80pLbePuhb/v3f7DQPjZqwk0H7wiF4UcET37oFt9uN39CYQFQGA+ml2y
3ncomJ9Jky3SCl1n9GGlqi/tYUYhUND8FGhDshoyvenIHAADd7Vm3LJr5DTLaAr6
ToeOni3A5PnZIx/sr8eUnnsCgYEAjDPJhU0C4zUvzx0/pjuhgi4KZP6NymvVDbJL
jaHTaT4p1GRhXbuY+ipySZYoPjp7t0UcQimZdQPY0lrp9mTvmHD1NnvC6w0jqA4z
cYuojE0Riwx3Tf2WgQqc9boOqSRr5uAzHH/R5VuoCy5GShuiHYDDDtoG9QpuCmDL
amjXtuECgYEAxkdsOAtmCihgDucHTht1zNImBNB/31+iZ1R3q78PkUwLWC5GGU/x
3nMsr2pvQgb1cC9Wdi8vAHz4bxDsPNzKJ1Tlyrxp1o4J8sJM64n3gY+HaGk3HRbQ
kLCBYOHSXIZVDr/GFND1zYDbMky/HNWFo0RxhEZL7ihtvugnHhGuOno=
-----END RSA PRIVATE KEY-----
`)
	caPrivateKey, err := ParsePrivateKeyFromPEM(pk)
	if err != nil {
		t.Errorf("could not parse private key, err: %s", err)

		return
	}

	type args struct {
		privKey          any
		constraintsByAlg map[Algorithm]BitSizeConstraints
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidatePrivateKey() returns no error if private key match constraints",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ValidatePrivateKey() returns error if private key doesn't match constraints",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 4096,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ValidatePrivateKey() returns error if missing constraints for that algorithm",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					ECDSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePrivateKey(tt.args.privKey, tt.args.constraintsByAlg); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseSubjectFromString(t *testing.T) {
	type args struct {
		subject string
	}
	tests := []struct {
		name    string
		args    args
		want    pkix.Name
		wantErr bool
	}{
		{
			name: "Send valid Subjec string",
			args: args{
				subject: pkix.Name{
					Country:      []string{"DE"},
					Province:     []string{"BA"},
					Organization: []string{"SAP"},
					CommonName:   "MyCert",
					SerialNumber: "01234556",
				}.String(),
			},
			want: pkix.Name{
				Country:      []string{"DE"},
				Province:     []string{"BA"},
				Organization: []string{"SAP"},
				CommonName:   "MyCert",
				SerialNumber: "01234556",
			},
			wantErr: false,
		},
		{
			name: "Use double comma and some spaces on Subject",
			args: args{
				subject: "SERIALNUMBER=01234556; CN=MyCert; O=SAP ;ST=BA ; C=DE",
			},
			want: pkix.Name{
				Country:      []string{"DE"},
				Province:     []string{"BA"},
				Organization: []string{"SAP"},
				CommonName:   "MyCert",
				SerialNumber: "01234556",
			},
			wantErr: false,
		},
		{
			name: "Invalid separator on some fields",
			args: args{
				subject: "SERIALNUMBER=01234556-CN=MyCert;O=SAP-ST=BA;C=DE",
			},
			want:    pkix.Name{},
			wantErr: true,
		},
		{
			name: "Invalid format string",
			args: args{
				subject: "SERIALNUMBER=01234556;WrongField=MyCert;O=SAP;ST=BA;C=DE",
			},
			want:    pkix.Name{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSubjectFromString(tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSubjectFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSubjectFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
