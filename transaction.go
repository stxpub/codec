package codec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"regexp"
)

type Decoder interface {
	Decode(*bytes.Reader) error
}

type Name string

// TODO: add regex checks
func (s *Name) Decode(r *bytes.Reader) error {
	l, err := r.ReadByte()
	if err != nil {
		return err
	}
	if l <= 0 || l > 128 {
		return fmt.Errorf("invalid string length: %d", l)
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	*s = Name(b)
	return nil
}

type NetworkVersion byte

// TODO: do the validation during decode but consider
// preserving the version byte. Instead of the enum, just
// implement Stringer.
const (
	Mainnet NetworkVersion = iota
	Testnet
)

func (v *NetworkVersion) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	// https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md#version-number
	if (b & 0x80) == 0 {
		*v = Mainnet
	} else {
		*v = Testnet
	}
	return nil
}

type ChainID uint32

func (c *ChainID) Decode(r *bytes.Reader) error {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return err
	}
	*c = ChainID(binary.BigEndian.Uint32(b))
	// https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md#chain-id
	// Only valid value for mainnet is 0x0. However, on testnets, it seems like Chain IDs can be anything.
	// if *c != 0 && *c != 1 {
	// 	return fmt.Errorf("invalid chain ID: %x, only valid values are 0 and 1", *c)
	// }
	return nil
}

type AuthorizationType byte

const (
	Standard  AuthorizationType = 0x04
	Sponsored AuthorizationType = 0x05
)

func (a *AuthorizationType) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*a = AuthorizationType(b)
	if *a != Standard && *a != Sponsored {
		return fmt.Errorf("invalid authorization type: %x %x", *a, b)
	}
	return nil
}

type HashMode byte

const (
	// hash160(public-key), same as bitcoin's p2pkh
	P2PKH HashMode = iota
	// hash160(multisig-redeem-script), same as bitcoin's multisig p2sh
	P2SH
	// hash160(segwit-program-00(p2pkh)), same as bitcoin's p2sh-p2wpkh
	P2WPKH
	// hash160(segwit-program-00(public-keys)), same as bitcoin's p2sh-p2wsh
	P2WSH
)

func (h *HashMode) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*h = HashMode(b)
	if *h != P2PKH && *h != P2SH && *h != P2WPKH && *h != P2WSH {
		// return fmt.Errorf("invalid hash mode: %x", *h)
		// TODO: hash mode / version can be 22 -- figure out what that is and handle it
		log.Printf("invalid hash mode: %x", *h)
	}
	return nil
}

type AddressVersion byte

const (
	MainnetSingleSig AddressVersion = 22 // P
	MainnetMultiSig  AddressVersion = 20 // M
	TestnetSingleSig AddressVersion = 26 // T
	TestnetMultiSig  AddressVersion = 21 // N
)

func (a *AddressVersion) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*a = AddressVersion(b)
	if *a != MainnetSingleSig && *a != MainnetMultiSig && *a != TestnetSingleSig && *a != TestnetMultiSig {
		return fmt.Errorf("invalid address version: %x", *a)
	}
	return nil
}

type Address struct {
	Version   AddressVersion
	HashBytes [20]byte
}

func (a *Address) Decode(r *bytes.Reader) error {
	if err := a.Version.Decode(r); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, a.HashBytes[:]); err != nil {
		return err
	}
	return nil
}

func (a *Address) ToStacks() string {
	s, e := c32CheckEncode(uint8(a.Version), a.HashBytes[:])
	if e != nil {
		log.Printf("error encoding address: %v", e)
	}
	return "S" + s
}

type SpendingCondition struct {
	HashMode           HashMode
	PubKeyHash         [20]byte
	Nonce              uint64
	Fee                uint64
	SingleSigCondition *SingleSigSpendingCondition
	MultiSigCondition  *MultiSigSpendingCondition
}

func (s *SpendingCondition) Decode(r *bytes.Reader) error {
	if err := s.HashMode.Decode(r); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, s.PubKeyHash[:]); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.Nonce); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.Fee); err != nil {
		return err
	}
	if s.HashMode == P2PKH || s.HashMode == P2WPKH {
		s.SingleSigCondition = new(SingleSigSpendingCondition)
		if err := s.SingleSigCondition.Decode(r); err != nil {
			return err
		}
	} else {
		s.MultiSigCondition = new(MultiSigSpendingCondition)
		if err := s.MultiSigCondition.Decode(r); err != nil {
			return err
		}
	}
	return nil
}

type TransactionAuthorization struct {
	Type             AuthorizationType
	OriginCondition  SpendingCondition
	SponsorCondition *SpendingCondition
}

func (a *TransactionAuthorization) Decode(r *bytes.Reader) error {
	if err := a.Type.Decode(r); err != nil {
		return err
	}
	if err := a.OriginCondition.Decode(r); err != nil {
		return err
	}
	if a.Type == Sponsored {
		a.SponsorCondition = new(SpendingCondition)
		if err := a.SponsorCondition.Decode(r); err != nil {
			return err
		}
	}
	return nil
}

type AnchorMode byte

const (
	AnchorBlock AnchorMode = iota + 1
	MicroBlock
	Any
)

func (a *AnchorMode) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*a = AnchorMode(b)
	if *a != AnchorBlock && *a != MicroBlock && *a != Any {
		return fmt.Errorf("invalid anchor mode: %x", *a)
	}
	return nil
}

type PostConditionMode byte

const (
	Allow PostConditionMode = iota + 1
	Deny
)

func (p *PostConditionMode) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*p = PostConditionMode(b)
	if *p != Allow && *p != Deny {
		return fmt.Errorf("invalid post condition mode: %x", *p)
	}
	return nil
}

type PostConditionType byte

const (
	STXPostCondition PostConditionType = iota
	FTPostCondition
	NFTPostCondition
)

// Implement Decode for PostConditionType
func (p *PostConditionType) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*p = PostConditionType(b)
	if *p != STXPostCondition && *p != FTPostCondition && *p != NFTPostCondition {
		return fmt.Errorf("invalid post condition type: %x", *p)
	}
	return nil
}

type PostCondition struct {
	Type PostConditionType
	STX  *STXPostConditionBody
	FT   *FTPostConditionBody
	NFT  *NFTPostConditionBody
}

// Implement Decode for PostCondition
func (p *PostCondition) Decode(r *bytes.Reader) error {
	if err := p.Type.Decode(r); err != nil {
		return err
	}
	switch p.Type {
	case STXPostCondition:
		p.STX = new(STXPostConditionBody)
		if err := p.STX.Decode(r); err != nil {
			return err
		}
	case FTPostCondition:
		p.FT = new(FTPostConditionBody)
		if err := p.FT.Decode(r); err != nil {
			return err
		}
	case NFTPostCondition:
		p.NFT = new(NFTPostConditionBody)
		if err := p.NFT.Decode(r); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid post condition type: %x", p.Type)
	}
	return nil
}

type Principal struct {
	Type         PrincipalType
	Address      Address
	ContractName Name
}

type PrincipalType byte

const (
	PrincipalStandard PrincipalType = 0x02
	PrincipalContract PrincipalType = 0x03
	RecipientStandard PrincipalType = 0x05
	RecipientContract PrincipalType = 0x06
)

// Implement Decode for PrincipalType
func (p *PrincipalType) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*p = PrincipalType(b)
	// if *p != PrincipalContract && *p != PrincipalStandard {
	// 	return fmt.Errorf("invalid principal type: %x", *p)
	// }
	return nil
}

// Implement Decode for Principal
func (p *Principal) Decode(r *bytes.Reader) error {
	if err := p.Type.Decode(r); err != nil {
		return err
	}
	if err := p.Address.Decode(r); err != nil {
		return err
	}
	if p.Type == PrincipalContract {
		if err := p.ContractName.Decode(r); err != nil {
			return err
		}
	}
	return nil
}

type FungibleConditionCode byte

const (
	SentEq FungibleConditionCode = iota + 1
	SentGt
	SentGe
	SentLt
	SentLe
)

// Implement Decode for FungibleConditionCode
func (f *FungibleConditionCode) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*f = FungibleConditionCode(b)
	if *f < SentEq || *f > SentLe {
		return fmt.Errorf("invalid fungible condition code: %x", *f)
	}
	return nil
}

type STXPostConditionBody struct {
	Principal Principal
	Code      FungibleConditionCode
	Amount    uint64
}

func (s *STXPostConditionBody) Decode(r *bytes.Reader) error {
	if err := s.Principal.Decode(r); err != nil {
		return err
	}
	if err := s.Code.Decode(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.Amount); err != nil {
		return err
	}
	return nil
}

type FTPostConditionBody struct {
	Principal Principal
	AssetInfo AssetInfo
	Code      FungibleConditionCode
	Amount    uint64
}

func (n *FTPostConditionBody) Decode(r *bytes.Reader) error {
	if err := n.Principal.Decode(r); err != nil {
		return err
	}
	if err := n.AssetInfo.Decode(r); err != nil {
		return err
	}
	if err := n.Code.Decode(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &n.Amount); err != nil {
		return err
	}
	return nil
}

type NFTConditionCode byte

const (
	Sent    NFTConditionCode = 0x10
	NotSent NFTConditionCode = 0x11
)

// Implement Decode for NFTConditionCode
func (n *NFTConditionCode) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*n = NFTConditionCode(b)
	if *n != Sent && *n != NotSent {
		return fmt.Errorf("invalid NFT condition code: %x", *n)
	}
	return nil
}

type NFTPostConditionBody struct {
	Principal Principal
	AssetInfo AssetInfo
	AssetName ClarityValue
	Code      NFTConditionCode
}

func (n *NFTPostConditionBody) Decode(r *bytes.Reader) error {
	if err := n.Principal.Decode(r); err != nil {
		return err
	}
	if err := n.AssetInfo.Decode(r); err != nil {
		return err
	}
	if v, e := decodeClarityValue(r); e != nil {
		return e
	} else {
		n.AssetName = v
	}
	if err := n.Code.Decode(r); err != nil {
		return err
	}
	return nil
}

type AssetInfo struct {
	Address      Address
	ContractName Name
	AssetName    Name
}

func (a *AssetInfo) Decode(r *bytes.Reader) error {
	if err := a.Address.Decode(r); err != nil {
		return err
	}
	if err := a.ContractName.Decode(r); err != nil {
		return err
	}
	if err := a.AssetName.Decode(r); err != nil {
		return err
	}
	return nil
}

type Transaction struct {
	Version           NetworkVersion
	CID               ChainID
	Authorization     TransactionAuthorization
	AnchorMode        AnchorMode
	PostConditionMode PostConditionMode
	PostConditions    []*PostCondition
	Payload           Payload
}

func (t *Transaction) Decode(r *bytes.Reader) error {
	if err := t.Version.Decode(r); err != nil {
		return err
	}
	if err := t.CID.Decode(r); err != nil {
		return err
	}
	if err := t.Authorization.Decode(r); err != nil {
		return err
	}
	if err := t.AnchorMode.Decode(r); err != nil {
		return err
	}
	if err := t.PostConditionMode.Decode(r); err != nil {
		return err
	}
	var pcCount uint32
	if err := binary.Read(r, binary.BigEndian, &pcCount); err != nil {
		return err
	}
	for i := uint32(0); i < pcCount; i++ {
		pc := new(PostCondition)
		if err := pc.Decode(r); err != nil {
			return err
		}
		t.PostConditions = append(t.PostConditions, pc)
	}
	if err := t.Payload.Decode(r); err != nil {
		return err
	}
	return nil
}

type PayloadType byte

const (
	TokenTransfer PayloadType = iota
	ContractDeploy
	ContractCall
	PoisonMicroblock
	Coinbase
	// https://github.com/stacksgov/sips/blob/main/sips/sip-015/sip-015-network-upgrade.md
	CoinbaseToAltRecipient
	VersionedContractDeploy
	// https://github.com/stacksgov/sips/blob/main/sips/sip-021/sip-021-nakamoto.md
	TenureChange
	NakamotoCoinbase
)

// Implement Decode for PayloadType
func (p *PayloadType) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	*p = PayloadType(b)
	if *p < TokenTransfer || *p > NakamotoCoinbase {
		return fmt.Errorf("invalid payload type: %x %x %x", *p, TokenTransfer, Coinbase)
	}
	return nil
}

type STXTransferPayload struct {
	Recipient Principal
	Amount    uint64
}

// Implement Decode for STXTransferPayload
func (s *STXTransferPayload) Decode(r *bytes.Reader) error {
	if err := s.Recipient.Decode(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &s.Amount); err != nil {
		return err
	}
	return nil
}

type ContractDeployPayload struct {
	ContractName Name
	CodeBody     string
}

// Implement Decode for ContractDeployPayload
func (c *ContractDeployPayload) Decode(r *bytes.Reader) error {
	if err := c.ContractName.Decode(r); err != nil {
		return err
	}
	var bodyLen uint32
	if err := binary.Read(r, binary.BigEndian, &bodyLen); err != nil {
		return err
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	c.CodeBody = string(body)
	return nil
}

type VersionedContractDeployPayload struct {
	ClarityVersion byte
	ContractDeployPayload
}

// Implement Decode for VersionedContractDeployPayload
func (v *VersionedContractDeployPayload) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	v.ClarityVersion = b
	if err := v.ContractDeployPayload.Decode(r); err != nil {
		return err
	}
	return nil
}

type ContractCallPayload struct {
	Origin   Address
	Contract Name
	Function Name
	// TODO: add decoding of args
}

// Implement Decode for ContractCallPayload
func (c *ContractCallPayload) Decode(r *bytes.Reader) error {
	if err := c.Origin.Decode(r); err != nil {
		return err
	}
	if err := c.Contract.Decode(r); err != nil {
		return err
	}
	if err := c.Function.Decode(r); err != nil {
		return err
	}
	return nil
}

type CoinbasePayload struct {
	Buffer [32]byte
}

// Implement Decode for CoinbasePayload
func (c *CoinbasePayload) Decode(r *bytes.Reader) error {
	if _, err := io.ReadFull(r, c.Buffer[:]); err != nil {
		return err
	}
	return nil
}

type TenureChangeCause byte

const (
	BlockFound TenureChangeCause = iota
	Extend
)

type TenureChangePayload struct {
	ConsensusHash          [20]byte
	PrevConsensusHash      [20]byte
	BurnchainConsensusHash [20]byte
	PrevTenureEnd          [32]byte
	Cause                  TenureChangeCause
	PubkeyHash             [20]byte
}

// Implement Decode for TenureChangePayload
func (t *TenureChangePayload) Decode(r *bytes.Reader) error {
	if _, err := io.ReadFull(r, t.ConsensusHash[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, t.PrevConsensusHash[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, t.BurnchainConsensusHash[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, t.PrevTenureEnd[:]); err != nil {
		return err
	}

	cause, err := r.ReadByte()
	if err != nil {
		return err
	}
	t.Cause = TenureChangeCause(cause)

	if _, err := io.ReadFull(r, t.PubkeyHash[:]); err != nil {
		return err
	}

	return nil
}

type Payload struct {
	Type                    PayloadType
	Transfer                *STXTransferPayload
	ContractDeploy          *ContractDeployPayload
	ContractCall            *ContractCallPayload
	Coinbase                *CoinbasePayload
	VersionedContractDeploy *VersionedContractDeployPayload
	TenureChange            *TenureChangePayload
}

// Implement Decode for Payload
func (p *Payload) Decode(r *bytes.Reader) error {
	if err := p.Type.Decode(r); err != nil {
		return err
	}
	switch p.Type {
	case TokenTransfer:
		p.Transfer = new(STXTransferPayload)
		if err := p.Transfer.Decode(r); err != nil {
			return err
		}
	case ContractDeploy:
		p.ContractDeploy = new(ContractDeployPayload)
		if err := p.ContractDeploy.Decode(r); err != nil {
			return err
		}
	case ContractCall:
		p.ContractCall = new(ContractCallPayload)
		if err := p.ContractCall.Decode(r); err != nil {
			return err
		}
	case Coinbase:
		p.Coinbase = new(CoinbasePayload)
		if err := p.Coinbase.Decode(r); err != nil {
			return err
		}
	case VersionedContractDeploy:
		p.VersionedContractDeploy = new(VersionedContractDeployPayload)
		if err := p.VersionedContractDeploy.Decode(r); err != nil {
			return err
		}
	case TenureChange:
		p.TenureChange = new(TenureChangePayload)
		if err := p.TenureChange.Decode(r); err != nil {
			return err
		}
	case NakamotoCoinbase:
		// not implemented yet, return err
		return fmt.Errorf("NakamotoCoinbase not implemented")
	default:
		return fmt.Errorf("invalid payload type: %x", p.Type)
	}
	return nil
}

type SingleSigSpendingCondition struct {
	PublicKeyEncoding byte
	Signature         [65]byte
}

// Implement Decode for SingleSigSpendingCondition
func (sssc *SingleSigSpendingCondition) Decode(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	// encoding can only be 0x00 or 0x01
	if b != 0x00 && b != 0x01 {
		return fmt.Errorf("invalid public key encoding %x", b)
	}
	sssc.PublicKeyEncoding = b
	if err := binary.Read(r, binary.BigEndian, &sssc.Signature); err != nil {
		return err
	}
	return nil
}

type MultiSigSpendingCondition struct {
	Authorizations []SpendingAuthorizationField
	SignatureCount uint16
}

// Implement Decode for MultiSigSpendingCondition
func (msc *MultiSigSpendingCondition) Decode(r *bytes.Reader) error {
	var fieldCount uint32
	if err := binary.Read(r, binary.BigEndian, &fieldCount); err != nil {
		return err
	}
	for i := uint32(0); i < fieldCount; i++ {
		var saf SpendingAuthorizationField
		if err := saf.Decode(r); err != nil {
			return err
		}
		msc.Authorizations = append(msc.Authorizations, saf)
	}

	// Decode SignatureCount
	if err := binary.Read(r, binary.BigEndian, &msc.SignatureCount); err != nil {
		return err
	}
	return nil
}

type SpendingAuthorizationField struct {
	FieldID byte
	Body    []byte
}

// Implement Decode for SpendingAuthorizationField
func (saf *SpendingAuthorizationField) Decode(r *bytes.Reader) error {
	saf.FieldID, _ = r.ReadByte()
	var len int
	if saf.FieldID == 0x00 || saf.FieldID == 0x01 {
		len = 33
	} else {
		// TODO: check FieldID should be 0x02 or 0x03
		len = 65
	}
	saf.Body = make([]byte, len)
	if _, err := io.ReadFull(r, saf.Body); err != nil {
		return err
	}
	return nil
}

func isValidContractName(name string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9]|[-_])*$", name)
	return match && len(name) <= 128
}

func isValidAssetName(name string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z]([a-zA-Z0-9]|[-_!?])*$", name)
	return match && len(name) <= 128
}
