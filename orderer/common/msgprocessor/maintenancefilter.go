/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msgprocessor

import (
	"bytes"

	"github.com/hyperledger/fabric/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/smartbft"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/orderer/consensus/smartbft/util"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

// MaintenanceFilterSupport provides the resources required for the maintenance filter.
type MaintenanceFilterSupport interface {
	// OrdererConfig returns the config.Orderer for the channel and whether the Orderer config exists
	OrdererConfig() (channelconfig.Orderer, bool)
	// ChannelID returns the ChannelID
	ChannelID() string
}

// MaintenanceFilter checks whether the orderer config ConsensusType is in maintenance mode, and if it is,
// validates that the transaction is signed by the orderer org admin.
type MaintenanceFilter struct {
	support MaintenanceFilterSupport
	// A set of permitted target consensus types
	permittedTargetConsensusTypes map[string]bool
	bccsp                         bccsp.BCCSP
}

// NewMaintenanceFilter creates a new maintenance filter, at every evaluation, the policy manager and orderer config
// are called to retrieve the latest version of the policy and config.
func NewMaintenanceFilter(support MaintenanceFilterSupport, bccsp bccsp.BCCSP) *MaintenanceFilter {
	mf := &MaintenanceFilter{
		support:                       support,
		permittedTargetConsensusTypes: make(map[string]bool),
		bccsp:                         bccsp,
	}
	mf.permittedTargetConsensusTypes["BFT"] = true
	return mf
}

// Apply applies the maintenance filter on a CONFIG tx.
func (mf *MaintenanceFilter) Apply(message *cb.Envelope) error {
	ordererConf, ok := mf.support.OrdererConfig()
	if !ok {
		logger.Panic("Programming error: orderer config not found")
	}

	configEnvelope := &cb.ConfigEnvelope{}
	chanHdr, err := protoutil.UnmarshalEnvelopeOfType(message, cb.HeaderType_CONFIG, configEnvelope)
	if err != nil {
		return errors.Wrap(err, "envelope unmarshalling failed")
	}

	logger.Debugw("Going to inspect maintenance mode transition rules",
		"ConsensusState", ordererConf.ConsensusState(), "channel", chanHdr.ChannelId)
	err = mf.inspect(configEnvelope, ordererConf)
	if err != nil {
		return errors.Wrap(err, "config transaction inspection failed")
	}

	return nil
}

// inspect checks whether the next orderer config, extracted from the incoming configEnvelope, respects the
// transition rules of consensus-type migration using maintenance-mode.
func (mf *MaintenanceFilter) inspect(configEnvelope *cb.ConfigEnvelope, ordererConfig channelconfig.Orderer) error {
	if configEnvelope.LastUpdate == nil {
		return errors.Errorf("updated config does not include a config update")
	}

	bundle, err := channelconfig.NewBundle(mf.support.ChannelID(), configEnvelope.Config, mf.bccsp)
	if err != nil {
		return errors.Wrap(err, "failed to parse config")
	}

	nextOrdererConfig, ok := bundle.OrdererConfig()
	if !ok {
		return errors.New("next config is missing orderer group")
	}

	if !ordererConfig.Capabilities().ConsensusTypeMigration() {
		if nextState := nextOrdererConfig.ConsensusState(); nextState != orderer.ConsensusType_STATE_NORMAL {
			return errors.Errorf("next config attempted to change ConsensusType.State to %s, but capability is disabled", nextState)
		}
		if ordererConfig.ConsensusType() != nextOrdererConfig.ConsensusType() {
			return errors.Errorf("next config attempted to change ConsensusType.Type from %s to %s, but capability is disabled",
				ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType())
		}
		return nil
	}

	// Entry to- and exit from- maintenance-mode should not be accompanied by any other change.
	if ordererConfig.ConsensusState() != nextOrdererConfig.ConsensusState() {
		if err1Change := mf.ensureConsensusTypeChangeOnly(configEnvelope); err1Change != nil {
			return err1Change
		}
		if ordererConfig.ConsensusType() != nextOrdererConfig.ConsensusType() {
			return errors.Errorf("attempted to change ConsensusType.Type from %s to %s, but ConsensusType.State is changing from %s to %s",
				ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType(), ordererConfig.ConsensusState(), nextOrdererConfig.ConsensusState())
		}
		if !bytes.Equal(nextOrdererConfig.ConsensusMetadata(), ordererConfig.ConsensusMetadata()) {
			return errors.Errorf("attempted to change ConsensusType.Metadata, but ConsensusType.State is changing from %s to %s",
				ordererConfig.ConsensusState(), nextOrdererConfig.ConsensusState())
		}
	}

	// ConsensusType.Type can only change in maintenance-mode, and only within the set of permitted types.
	// Note: only etcdraft to BFT transitions are supported.
	if ordererConfig.ConsensusType() != nextOrdererConfig.ConsensusType() {
		if ordererConfig.ConsensusState() == orderer.ConsensusType_STATE_NORMAL {
			return errors.Errorf("attempted to change consensus type from %s to %s, but current config ConsensusType.State is not in maintenance mode",
				ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType())
		}
		if nextOrdererConfig.ConsensusState() == orderer.ConsensusType_STATE_NORMAL {
			return errors.Errorf("attempted to change consensus type from %s to %s, but next config ConsensusType.State is not in maintenance mode",
				ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType())
		}

		if !mf.permittedTargetConsensusTypes[nextOrdererConfig.ConsensusType()] {
			return errors.Errorf("attempted to change consensus type from %s to %s, transition not supported",
				ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType())
		}

		if nextOrdererConfig.ConsensusType() == "BFT" {
			updatedMetadata := &smartbft.Options{}
			if err := proto.Unmarshal(nextOrdererConfig.ConsensusMetadata(), updatedMetadata); err != nil {
				return errors.Wrap(err, "failed to unmarshal BFT metadata configuration")
			}

			_, err := util.ConfigFromMetadataOptions(1, updatedMetadata)
			if err != nil {
				return errors.New("invalid BFT metadata configuration")
			}

			err = validateBFTConsenterMapping(ordererConfig, nextOrdererConfig)
			if err != nil {
				return errors.Wrap(err, "invalid BFT consenter mapping configuration")
			}
		}

		logger.Infof("[channel: %s] consensus-type migration: about to change from %s to %s",
			mf.support.ChannelID(), ordererConfig.ConsensusType(), nextOrdererConfig.ConsensusType())
	}

	if nextOrdererConfig.ConsensusState() != ordererConfig.ConsensusState() {
		logger.Infof("[channel: %s] maintenance mode: ConsensusType.State about to change from %s to %s",
			mf.support.ChannelID(), ordererConfig.ConsensusState(), nextOrdererConfig.ConsensusState())
	}

	return nil
}

// ensureConsensusTypeChangeOnly checks that the only change is the Channel/Orderer group, and within that,
// only to the ConsensusType value.
func (mf *MaintenanceFilter) ensureConsensusTypeChangeOnly(configEnvelope *cb.ConfigEnvelope) error {
	configUpdateEnv, err := protoutil.EnvelopeToConfigUpdate(configEnvelope.LastUpdate)
	if err != nil {
		return errors.Wrap(err, "envelope to config update unmarshalling error")
	}

	configUpdate, err := configtx.UnmarshalConfigUpdate(configUpdateEnv.ConfigUpdate)
	if err != nil {
		return errors.Wrap(err, "config update unmarshalling error")
	}

	if len(configUpdate.WriteSet.Groups) == 0 {
		return errors.New("config update contains no changes")
	}

	if len(configUpdate.WriteSet.Values) > 0 {
		return errors.Errorf("config update contains changes to values in group %s", channelconfig.ChannelGroupKey)
	}

	if len(configUpdate.WriteSet.Groups) > 1 {
		return errors.New("config update contains changes to more than one group")
	}

	if ordGroup, ok1 := configUpdate.WriteSet.Groups[channelconfig.OrdererGroupKey]; ok1 {
		if len(ordGroup.Groups) > 0 {
			return errors.Errorf("config update contains changes to groups within the %s group",
				channelconfig.OrdererGroupKey)
		}

		if _, ok2 := ordGroup.Values[channelconfig.ConsensusTypeKey]; !ok2 {
			return errors.Errorf("config update does not contain the %s value", channelconfig.ConsensusTypeKey)
		}

		if len(ordGroup.Values) > 1 {
			return errors.Errorf("config update contain more then just the %s value in the %s group",
				channelconfig.ConsensusTypeKey, channelconfig.OrdererGroupKey)
		}
	} else {
		return errors.Errorf("update does not contain the %s group", channelconfig.OrdererGroupKey)
	}

	return nil
}

func validateBFTConsenterMapping(currentOrdererConfig channelconfig.Orderer, nextOrdererConfig channelconfig.Orderer) error {
	// extract raft consenters from consensusTypeValue.metadata
	raftMetadata := &etcdraft.ConfigMetadata{}
	proto.Unmarshal(currentOrdererConfig.ConsensusMetadata(), raftMetadata)
	raftConsenters := raftMetadata.GetConsenters()

	// extract bft consenters
	bftConsenters := nextOrdererConfig.Consenters()

	if len(bftConsenters) == 0 {
		return errors.Errorf("Invalid new config: bft consenters are missing")
	}

	if len(raftConsenters) != len(bftConsenters) {
		return errors.Errorf("Invalid new config: the number of bft consenters: %d is not equal to the number of raft consenters: %d", len(bftConsenters), len(raftConsenters))
	}

	for _, raftConsenter := range raftConsenters {
		flag := false
		for _, bftConsenter := range bftConsenters {
			if raftConsenter.Port == bftConsenter.Port && raftConsenter.Host == bftConsenter.Host &&
				bytes.Equal(raftConsenter.ServerTlsCert, bftConsenter.ServerTlsCert) &&
				bytes.Equal(raftConsenter.ClientTlsCert, bftConsenter.ClientTlsCert) {
				flag = true
				break
			}
		}
		if !flag {
			return errors.Errorf("No suitable BFT consenter for Raft consenter: %v", raftConsenter)
		}
	}

	return nil
}
