/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gossip

import (
	"bytes"
	"fmt"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	pcommon "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/common"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

var mcsLogger = flogging.MustGetLogger("peer.gossip.mcs")

// Hasher is the interface provides the hash function should be used for all gossip components.
type Hasher interface {
	Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error)
}

type ChannelConfigGetter func(cid string) channelconfig.Resources

// MSPMessageCryptoService implements the MessageCryptoService interface
// using the peer MSPs (local and channel-related)
//
// In order for the system to be secure it is vital to have the
// MSPs to be up-to-date. Channels' MSPs are updated via
// configuration transactions distributed by the ordering service.
//
// A similar mechanism needs to be in place to update the local MSP, as well.
// This implementation assumes that these mechanisms are all in place and working.
type MSPMessageCryptoService struct {
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter
	localSigner                identity.SignerSerializer
	deserializer               DeserializersManager
	hasher                     Hasher
	channelConfigGetter        ChannelConfigGetter
}

// NewMCS creates a new instance of MSPMessageCryptoService
// that implements MessageCryptoService.
// The method takes in input:
// 1. a policies.ChannelPolicyManagerGetter that gives access to the policy manager of a given channel via the Manager method.
// 2. an instance of identity.SignerSerializer
// 3. an identity deserializer manager
func NewMCS(
	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter,
	localSigner identity.SignerSerializer,
	deserializer DeserializersManager,
	hasher Hasher,
	channelConfigGetter ChannelConfigGetter,
) *MSPMessageCryptoService {
	return &MSPMessageCryptoService{
		channelPolicyManagerGetter: channelPolicyManagerGetter,
		localSigner:                localSigner,
		deserializer:               deserializer,
		hasher:                     hasher,
		channelConfigGetter:        channelConfigGetter,
	}
}

// ValidateIdentity validates the identity of a remote peer.
// If the identity is invalid, revoked, expired it returns an error.
// Else, returns nil
func (s *MSPMessageCryptoService) ValidateIdentity(peerIdentity api.PeerIdentityType) error {
	// As prescribed by the contract of method,
	// below we check only that peerIdentity is not
	// invalid, revoked or expired.

	_, _, err := s.getValidatedIdentity(peerIdentity)
	return err
}

// GetPKIidOfCert returns the PKI-ID of a peer's identity
// If any error occurs, the method return nil
// The PKid of a peer is computed as the SHA2-256 of peerIdentity which
// is supposed to be the serialized version of MSP identity.
// This method does not validate peerIdentity.
// This validation is supposed to be done appropriately during the execution flow.
func (s *MSPMessageCryptoService) GetPKIidOfCert(peerIdentity api.PeerIdentityType) common.PKIidType {
	// Validate arguments
	if len(peerIdentity) == 0 {
		mcsLogger.Error("Invalid Peer Identity. It must be different from nil.")

		return nil
	}

	sid, err := s.deserializer.Deserialize(peerIdentity)
	if err != nil {
		mcsLogger.Errorf("Failed getting validated identity from peer identity %s: [%s]", peerIdentity, err)

		return nil
	}

	// concatenate msp-id and idbytes
	// idbytes is the low-level representation of an identity.
	// it is supposed to be already in its minimal representation

	mspIDRaw := []byte(sid.Mspid)
	raw := append(mspIDRaw, sid.IdBytes...)

	// Hash
	digest, err := s.hasher.Hash(raw, &bccsp.SHA256Opts{})
	if err != nil {
		mcsLogger.Errorf("Failed computing digest of serialized identity %s: [%s]", peerIdentity, err)
		return nil
	}

	return digest
}

// VerifyBlock returns nil if the block is properly signed, and the claimed seqNum is the
// sequence number that the block's header contains.
// else returns error
func (s *MSPMessageCryptoService) VerifyBlock(chainID common.ChannelID, seqNum uint64, block *pcommon.Block) error {
	if block.Header == nil {
		return fmt.Errorf("Invalid Block on channel [%s]. Header must be different from nil.", chainID)
	}

	blockSeqNum := block.Header.Number
	if seqNum != blockSeqNum {
		return fmt.Errorf("Claimed seqNum is [%d] but actual seqNum inside block is [%d]", seqNum, blockSeqNum)
	}

	// - Extract channelID and compare with chainID
	channelID, err := protoutil.GetChannelIDFromBlock(block)
	if err != nil {
		return fmt.Errorf("Failed getting channel id from block with id [%d] on channel [%s]: [%s]", block.Header.Number, chainID, err)
	}

	if channelID != string(chainID) {
		return fmt.Errorf("Invalid block's channel id. Expected [%s]. Given [%s]", chainID, channelID)
	}

	// - Unmarshal medatada
	if block.Metadata == nil || len(block.Metadata.Metadata) == 0 {
		return fmt.Errorf("Block with id [%d] on channel [%s] does not have metadata. Block not valid.", block.Header.Number, chainID)
	}

	dataHash, err := protoutil.BlockDataHash(block.Data)
	if err != nil {
		return err
	}
	// - Verify that Header.DataHash is equal to the hash of block.Data
	// This is to ensure that the header is consistent with the data carried by this block
	if !bytes.Equal(dataHash, block.Header.DataHash) {
		return fmt.Errorf("Header.DataHash is different from Hash(block.Data) for block with id [%d] on channel [%s]", block.Header.Number, chainID)
	}

	return s.verifyHeaderAndMetadata(channelID, block)
}

func (s *MSPMessageCryptoService) verifyHeaderAndMetadata(channelID string, block *pcommon.Block) error {
	// Get the policy manager for channelID
	cpm := s.channelPolicyManagerGetter.Manager(channelID)
	if cpm == nil {
		return fmt.Errorf("Could not acquire policy manager for channel %s", channelID)
	}
	mcsLogger.Debugf("Got policy manager for channel [%s]", channelID)

	// Get block validation policy
	policy, ok := cpm.GetPolicy(policies.BlockValidation)
	// ok is true if it was the policy requested, or false if it is the default policy
	mcsLogger.Debugf("Got block validation policy for channel [%s] with flag [%t]", channelID, ok)

	chConfig := s.channelConfigGetter(channelID)
	bftEnabled := chConfig.ChannelConfig().Capabilities().ConsensusTypeBFT()

	var consenters []*pcommon.Consenter
	if bftEnabled {
		cfg, ok := chConfig.OrdererConfig()
		if !ok {
			return fmt.Errorf("no orderer section in channel config for channel [%s].", channelID)
		}
		consenters = cfg.Consenters()
	}

	verifier := protoutil.BlockSignatureVerifier(bftEnabled, consenters, policy)
	return verifier(block.Header, block.Metadata)
}

// VerifyBlockAttestation returns nil when the header matches the metadata signature. It assumed the block.Data is nil
// and therefore does not verify that Header.DataHash is equal to the hash of block.Data. This is used when the orderer
// delivers a block with header & metadata only, as an attestation of block existence.
func (s *MSPMessageCryptoService) VerifyBlockAttestation(chainID string, block *pcommon.Block) error {
	if block == nil {
		return fmt.Errorf("Invalid Block on channel [%s]. Block is nil.", chainID)
	}
	if block.Header == nil {
		return fmt.Errorf("Invalid Block on channel [%s]. Header must be different from nil.", chainID)
	}

	// - Unmarshal medatada
	if block.Metadata == nil || len(block.Metadata.Metadata) == 0 {
		return fmt.Errorf("Block with id [%d] on channel [%s] does not have metadata. Block not valid.", block.Header.Number, chainID)
	}

	return s.verifyHeaderAndMetadata(chainID, block)
}

// Sign signs msg with this peer's signing key and outputs
// the signature if no error occurred.
func (s *MSPMessageCryptoService) Sign(msg []byte) ([]byte, error) {
	return s.localSigner.Sign(msg)
}

// Verify checks that signature is a valid signature of message under a peer's verification key.
// If the verification succeeded, Verify returns nil meaning no error occurred.
// If peerIdentity is nil, then the verification fails.
func (s *MSPMessageCryptoService) Verify(peerIdentity api.PeerIdentityType, signature, message []byte) error {
	identity, chainID, err := s.getValidatedIdentity(peerIdentity)
	if err != nil {
		mcsLogger.Errorf("Failed getting validated identity from peer identity [%s]", err)

		return err
	}

	if len(chainID) == 0 {
		// At this stage, this means that peerIdentity
		// belongs to this peer's LocalMSP.
		// The signature is validated directly
		return identity.Verify(message, signature)
	}

	// At this stage, the signature must be validated
	// against the reader policy of the channel
	// identified by chainID

	return s.VerifyByChannel(chainID, peerIdentity, signature, message)
}

// VerifyByChannel checks that signature is a valid signature of message
// under a peer's verification key, but also in the context of a specific channel.
// If the verification succeeded, Verify returns nil meaning no error occurred.
// If peerIdentity is nil, then the verification fails.
func (s *MSPMessageCryptoService) VerifyByChannel(chainID common.ChannelID, peerIdentity api.PeerIdentityType, signature, message []byte) error {
	// Validate arguments
	if len(peerIdentity) == 0 {
		return errors.New("Invalid Peer Identity. It must be different from nil.")
	}

	// Get the policy manager for channel chainID
	cpm := s.channelPolicyManagerGetter.Manager(string(chainID))
	if cpm == nil {
		return fmt.Errorf("Could not acquire policy manager for channel %s", string(chainID))
	}
	mcsLogger.Debugf("Got policy manager for channel [%s]", string(chainID))

	// Get channel reader policy
	policy, flag := cpm.GetPolicy(policies.ChannelApplicationReaders)
	mcsLogger.Debugf("Got reader policy for channel [%s] with flag [%t]", string(chainID), flag)

	return policy.EvaluateSignedData(
		[]*protoutil.SignedData{{
			Data:      message,
			Identity:  peerIdentity,
			Signature: signature,
		}},
	)
}

func (s *MSPMessageCryptoService) Expiration(peerIdentity api.PeerIdentityType) (time.Time, error) {
	id, _, err := s.getValidatedIdentity(peerIdentity)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "Unable to extract msp.Identity from peer Identity")
	}
	return id.ExpiresAt(), nil
}

func (s *MSPMessageCryptoService) getValidatedIdentity(peerIdentity api.PeerIdentityType) (msp.Identity, common.ChannelID, error) {
	// Validate arguments
	if len(peerIdentity) == 0 {
		return nil, nil, errors.New("Invalid Peer Identity. It must be different from nil.")
	}

	sId, err := s.deserializer.Deserialize(peerIdentity)
	if err != nil {
		mcsLogger.Error("failed deserializing identity", err)
		return nil, nil, err
	}

	// Notice that peerIdentity is assumed to be the serialization of an identity.
	// So, first step is the identity deserialization and then verify it.

	// First check against the local MSP.
	// If the peerIdentity is in the same organization of this node then
	// the local MSP is required to take the final decision on the validity
	// of the signature.
	lDes := s.deserializer.GetLocalDeserializer()
	identity, err := lDes.DeserializeIdentity(peerIdentity)
	if err == nil {
		// No error means that the local MSP successfully deserialized the identity.
		// We now check additional properties.
		if err := lDes.IsWellFormed(sId); err != nil {
			return nil, nil, errors.Wrap(err, "identity is not well formed")
		}
		// TODO: The following check will be replaced by a check on the organizational units
		// when we allow the gossip network to have organization unit (MSP subdivisions)
		// scoped messages.
		// The following check is consistent with the SecurityAdvisor#OrgByPeerIdentity
		// implementation.
		// TODO: Notice that the following check saves us from the fact
		// that DeserializeIdentity does not yet enforce MSP-IDs consistency.
		// This check can be removed once DeserializeIdentity will be fixed.
		if identity.GetMSPIdentifier() == s.deserializer.GetLocalMSPIdentifier() {
			// Check identity validity

			// Notice that at this stage we don't have to check the identity
			// against any channel's policies.
			// This will be done by the caller function, if needed.
			return identity, nil, identity.Validate()
		}
	}

	// Check against managers
	for chainID, mspManager := range s.deserializer.GetChannelDeserializers() {
		// Deserialize identity
		identity, err := mspManager.DeserializeIdentity(peerIdentity)
		if err != nil {
			mcsLogger.Debugf("Failed deserialization identity %s on [%s]: [%s]", peerIdentity, chainID, err)
			continue
		}

		// We managed deserializing the identity with this MSP manager. Now we check if it's well formed.
		if err := mspManager.IsWellFormed(sId); err != nil {
			return nil, nil, errors.Wrap(err, "identity is not well formed")
		}

		// Check identity validity
		// Notice that at this stage we don't have to check the identity
		// against any channel's policies.
		// This will be done by the caller function, if needed.

		if err := identity.Validate(); err != nil {
			mcsLogger.Debugf("Failed validating identity %s on [%s]: [%s]", peerIdentity, chainID, err)
			continue
		}

		mcsLogger.Debugf("Validation succeeded %s on [%s]", peerIdentity, chainID)

		return identity, common.ChannelID(chainID), nil
	}

	return nil, nil, fmt.Errorf("Peer Identity %s cannot be validated. No MSP found able to do that.", peerIdentity)
}
