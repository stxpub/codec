package codec

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Token Transfer",
			input: "00000000010400c1c66bdc612ebf90fd9b343f31f7f1750e50a13b000000000000333b00000000000000c80001989e4de49bada3b7b718d5c329ac6bee4009e1cece5a5268daa7b548af947b0a3edf080e2ea61c05405171b175c3bbcd5c2ef8ce12d81066bad86e019370faf00302000000000005163cbbe96167252efb851181018067a5ae2833e28800000000000000016d6f72616e6765313030300000000000000000000000000000000000000000000000",
		},
		{
			name:  "Contract Call with PostCondtions",
			input: "00000000010400fca819a10aea212709b03a029bebeb42e58629f4000000000000001b000000000000b2eb0001e577499db257142fda8ab8a1ba1599aaabaa7c101006e1ef43bc1daf686356cb6f990334ea7c87a67725ce8540b15b3bc53a31ca499fb246dc18fcf3c08a97ff030200000003010216fca819a10aea212709b03a029bebeb42e58629f4162ec1a2dc2904ebc8b408598116c75e42c51afa26187374782d73747374782d6c702d746f6b656e2d762d312d320d7374782d73747374782d6c7074010000000008e52e510003162ec1a2dc2904ebc8b408598116c75e42c51afa261a737461626c65737761702d7374782d73747374782d762d312d320300000000054254fc0103162ec1a2dc2904ebc8b408598116c75e42c51afa261a737461626c65737761702d7374782d73747374782d762d312d3216099fb88926d82f30b2f40eaf3ee423cb725bdb3b0b73747374782d746f6b656e0573747374780300000000038f49e002162ec1a2dc2904ebc8b408598116c75e42c51afa261a737461626c65737761702d7374782d73747374782d762d312d321277697468647261772d6c6971756964697479000000050616099fb88926d82f30b2f40eaf3ee423cb725bdb3b0b73747374782d746f6b656e06162ec1a2dc2904ebc8b408598116c75e42c51afa26187374782d73747374782d6c702d746f6b656e2d762d312d320100000000000000000000000008e52e5101000000000000000000000000054254fc01000000000000000000000000038f49e0",
		},
		{
			name:  "Coinbase payload",
			input: "000000000104002ceecedbeb1b0ee7d96b0e5c64bd48dadf75ab840000000000000b7200000000000000000000a9ae16e784730b38feb724515fcfa76998a6e2f9a36d7a5171aceb90c810502d6604447beaec0d806e45871fec5202af3ba9985d2647f7ac72199d632214d2af010200000000040000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:  "Contract deploy",
			input: "000000000104008d6fc0c16c4c63f59d2875faae3da1230250cb1400000000000015a900000000000f4240000128e2c98696970790763ddd400b91570c6445ed9a8389aac85d097d42d87d60ee1325114570c7347ef0d9d40c645d18d06cca2865c0f2675a76eda914694f783c0302000000000602126c6973742d6564656c636f696e2d65646c630000049b28646566696e652d7075626c6963202865786563757465202873656e646572207072696e636970616c29290a202028626567696e0a202020203b3b20656e61626c652074686520746f6b656e20666f72207374616b696e670a2020202028747279212028636f6e74726163742d63616c6c3f20275350325a4e474a3835454e44593651524851355032443446584b475a57434b54423254305a35354b532e6c616e6473207365742d77686974656c6973746564202753503236505a47363144483636375843583531545a4e4248584d344847344d3642324857564d3437562e6564656c636f696e207472756529290a20202020286c6574200a202020202020280a20202020202020203b3b20637265617465206120756e6971756520696420666f7220746865207374616b656420746f6b656e0a2020202020202020286c616e642d69642028747279212028636f6e74726163742d63616c6c3f20275350325a4e474a3835454e44593651524851355032443446584b475a57434b54423254305a35354b532e6c616e6473206765742d6f722d6372656174652d6c616e642d6964202753503236505a47363144483636375843583531545a4e4248584d344847344d3642324857564d3437562e6564656c636f696e2929290a20202020202020203b3b206c6f6f6b75702074686520746f74616c20737570706c79206f6620746865207374616b656420746f6b656e0a202020202020202028746f74616c2d737570706c792028756e777261702d70616e69632028636f6e74726163742d63616c6c3f202753503236505a47363144483636375843583531545a4e4248584d344847344d3642324857564d3437562e6564656c636f696e206765742d746f74616c2d737570706c792929290a20202020202020203b3b2063616c63756c6174652074686520696e697469616c20646966666963756c7479206261736564206f6e2074686520746f74616c20737570706c790a2020202020202020286c616e642d646966666963756c747920282f20746f74616c2d737570706c792028706f77207531302075352929290a202020202020290a202020202020287072696e74207b6576656e743a2022656e61626c652d6c697374696e67222c20636f6e74726163743a202253503236505a47363144483636375843583531545a4e4248584d344847344d3642324857564d3437562e6564656c636f696e222c206c616e642d69643a206c616e642d69642c20746f74616c2d737570706c793a20746f74616c2d737570706c792c206c616e642d646966666963756c74793a206c616e642d646966666963756c74797d290a2020202020203b3b2073657420696e697469616c20646966666963756c7479206261736564206f6e20746f74616c20737570706c7920746f206e6f726d616c697a6520656e65726779206f75747075740a20202020202028636f6e74726163742d63616c6c3f20275350325a4e474a3835454e44593651524851355032443446584b475a57434b54423254305a35354b532e6c616e6473207365742d6c616e642d646966666963756c7479206c616e642d6964206c616e642d646966666963756c7479290a20202020290a2020290a290a",
		},
		{
			name:  "Fixme",
			input: "00000000010400f41a05121efa01a279f5ac5810a0e6f9c825e98100000000000004850000000000001a39000066a41424ccfbb0de08446086ede915cf32c8d86244664f8cbc3495fca91d9bb735baa7751ae5a45e9102c37f6d0e0e776a91013f9b162a60c59c546caaa727aa030200000003010216f41a05121efa01a279f5ac5810a0e6f9c825e98116eae2820eebe09cfe1ad1436203a264fd9f958c271477656c7368636f726769636f696e2d746f6b656e0e77656c7368636f726769636f696e03000000f9c23c6e48020216f41a05121efa01a279f5ac5810a0e6f9c825e98116bf584905755be35f11b96c2691fd9c3fc64f4b16056c616e6473046c616e640c00000002076c616e642d69640100000000000000000000000000000004056f776e65720516f41a05121efa01a279f5ac5810a0e6f9c825e98110010216f41a05121efa01a279f5ac5810a0e6f9c825e98116bf584905755be35f11b96c2691fd9c3fc64f4b16166c69717569642d7374616b65642d6368617269736d61136c69717569642d7374616b65642d746f6b656e0300000000000000010216bf584905755be35f11b96c2691fd9c3fc64f4b160e6c616e642d68656c7065722d7632047772617000000002010000000000000000000000f9c23c6e480616eae2820eebe09cfe1ad1436203a264fd9f958c271477656c7368636f726769636f696e2d746f6b656e",
		},
		{
			name:  "Fixme too",
			input: "00000000010400c9b312d56d425197006d8c072f3d566519c8b58a000000000000073b0000000000000bb8000034c7527ce17586aad93fb1485083ec10c9184bda63f18676d8a30ec604efb18f25ef86f5e284cdee13d2398a973d5e6fac2488ab1236c37c77b63c8304f24edf030200000001020216c9b312d56d425197006d8c072f3d566519c8b58a16c9b312d56d425197006d8c072f3d566519c8b58a076d656d706f6f6c076d656d706f6f6c0100000000000000000000000000000072100216c9b312d56d425197006d8c072f3d566519c8b58a076d656d706f6f6c087472616e736665720000000301000000000000000000000000000000720516c9b312d56d425197006d8c072f3d566519c8b58a051638c216c895ec1dc1356d6d237fb6dfc9dec26034",
		},
		{
			name:  "multisig",
			input: "0000000001040131825b188c6fe1c7423c3812b431a1412cf6d2b800000000000000010000000000000d4000000003020118d2603983abc862d8eaf136e79a1a85805fa4fbe85fffe908d7062a356c849f7fbd5225826f033f69d8476173bc15cbacfcaf9a3dbd9fb00734175f2e184183000391bfea141e9e822a36131e3029c3da8389632a74fd4b1896914f317e88542c670201d0a7323f87656c3d80da3521d50558213e71d33dad7242714f497a7bb38a95a743380ef5684b05721a7bb7f497fddb338fc3c5481be0b09848c3b58178f22a9f000203020000000000051420c9d4c526145267c51ae0c9337f3cbd6ae82b850000001e4401fd8030000000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.input)
			assert.NoError(t, err)

			var tx Transaction
			err = tx.Decode(bytes.NewReader(data))
			assert.NoError(t, err)
			t.Logf("%+v\n", tx)
		})
	}
}

func TestNetworkVersionDecode(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected NetworkVersion
		hasError bool
	}{
		{
			name:     "Mainnet",
			input:    []byte{0x00},
			expected: Mainnet,
			hasError: false,
		},
		{
			name:     "Testnet",
			input:    []byte{0x80},
			expected: Testnet,
			hasError: false,
		},
		{
			name:     "Invalid Input",
			input:    []byte{},
			expected: Mainnet,
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v NetworkVersion
			r := bytes.NewReader(tc.input)
			err := v.Decode(r)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

func TestAddresses(t *testing.T) {
	hexStrs := []string{
		"a46ff88886c2ef9762d970b4d2c63678835bd39d",
		"0000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000001",
		"1000000000000000000000000000000000000001",
		"1000000000000000000000000000000000000000",
	}

	versions := []AddressVersion{MainnetSingleSig, MainnetMultiSig, TestnetSingleSig, TestnetMultiSig}

	c32Addrs := [][]string{
		{
			"SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
			"SP000000000000000000002Q6VF78",
			"SP00000000000000000005JA84HQ",
			"SP80000000000000000000000000000004R0CMNV",
			"SP800000000000000000000000000000033H8YKK",
		},
		{
			"SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
			"SM0000000000000000000062QV6X",
			"SM00000000000000000005VR75B2",
			"SM80000000000000000000000000000004WBEWKC",
			"SM80000000000000000000000000000000JGSYGV",
		},
		{
			"ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ",
			"ST000000000000000000002AMW42H",
			"ST000000000000000000042DB08Y",
			"ST80000000000000000000000000000006BYJ4R4",
			"ST80000000000000000000000000000002YBNPV3",
		},
		{
			"SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9",
			"SN000000000000000000003YDHWKJ",
			"SN00000000000000000005341MC8",
			"SN800000000000000000000000000000066KZWY0",
			"SN800000000000000000000000000000006H75AK",
		},
	}

	for i, h := range hexStrs {
		for j, v := range versions {
			b, err := hex.DecodeString(h)
			assert.NoError(t, err)

			addr := Address{Version: v}
			copy(addr.HashBytes[:], b)
			z := addr.ToStacks()
			assert.NoError(t, err)
			assert.Equal(t, c32Addrs[j][i], z)
		}
	}
}
func TestChainIDDecode(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected ChainID
		hasError bool
	}{
		{
			name:     "Valid Chain ID",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: ChainID(0),
			hasError: false,
		},
		{
			name:     "Valid Chain ID",
			input:    []byte{0x00, 0x00, 0x00, 0x01},
			expected: ChainID(1),
			hasError: false,
		},
		{
			name:     "Incomplete Input",
			input:    []byte{0x00, 0x00, 0x00},
			expected: ChainID(0),
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c ChainID
			r := bytes.NewReader(tc.input)
			err := c.Decode(r)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, c)
			}
		})
	}
}