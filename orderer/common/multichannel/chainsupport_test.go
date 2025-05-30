/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package multichannel

import (
	"testing"

	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	msgprocessormocks "github.com/hyperledger/fabric/orderer/common/msgprocessor/mocks"
	"github.com/hyperledger/fabric/orderer/common/multichannel/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestConsensusMetadataValidation(t *testing.T) {
	oldConsensusMetadata := []byte("old consensus metadata")
	newConsensusMetadata := []byte("new consensus metadata")
	mockValidator := &mocks.ConfigTXValidator{}
	mockValidator.ChannelIDReturns("mychannel")
	mockValidator.ProposeConfigUpdateReturns(testConfigEnvelope(t), nil)
	mockOrderer := &mocks.OrdererConfig{}
	mockOrderer.ConsensusMetadataReturns(oldConsensusMetadata)
	mockResources := &mocks.Resources{}
	mockResources.ConfigtxValidatorReturns(mockValidator)
	mockResources.OrdererConfigReturns(mockOrderer, true)
	mockChannelConfig := &mocks.ChannelConfig{}
	mockChannelConfig.OrdererAddressesReturns([]string{"127.0.0.1"})
	mockChannelCapabilities := &mocks.ChannelCapabilities{}
	mockChannelCapabilities.ConsensusTypeBFTReturns(true)
	mockChannelConfig.CapabilitiesReturns(mockChannelCapabilities)
	mockResources.ChannelConfigReturns(mockChannelConfig)

	ms := &mutableResourcesMock{
		Resources:               mockResources,
		newConsensusMetadataVal: newConsensusMetadata,
	}
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	require.NoError(t, err)
	mv := &msgprocessormocks.MetadataValidator{}
	cs := &ChainSupport{
		ledgerResources: &ledgerResources{
			configResources: &configResources{
				mutableResources: ms,
				bccsp:            cryptoProvider,
			},
		},
		MetadataValidator: mv,
		BCCSP:             cryptoProvider,
	}

	// case 1: valid consensus metadata update
	_, err = cs.ProposeConfigUpdate(&common.Envelope{})
	require.NoError(t, err)

	// validate arguments to ValidateConsensusMetadata
	require.Equal(t, 1, mv.ValidateConsensusMetadataCallCount())
	om, nm, nc := mv.ValidateConsensusMetadataArgsForCall(0)
	require.False(t, nc)
	require.Equal(t, oldConsensusMetadata, om.ConsensusMetadata())
	require.Equal(t, newConsensusMetadata, nm.ConsensusMetadata())

	// case 2: invalid consensus metadata update
	mv.ValidateConsensusMetadataReturns(errors.New("bananas"))
	_, err = cs.ProposeConfigUpdate(&common.Envelope{})
	require.EqualError(t, err, "consensus metadata update for channel config update is invalid: bananas")
}

func TestBundleValidation(t *testing.T) {
	mockValidator := &mocks.ConfigTXValidator{}
	mockValidator.ChannelIDReturns("mychannel")
	mockValidator.ProposeConfigUpdateReturns(testConfigEnvelope(t), nil)

	mockResources := &mocks.Resources{}
	mockResources.ConfigtxValidatorReturns(mockValidator)

	mockChannelConfig := &mocks.ChannelConfig{}
	mockChannelConfig.OrdererAddressesReturns([]string{"127.0.0.1"})

	mockChannelCapabilities := &mocks.ChannelCapabilities{}
	mockChannelCapabilities.ConsensusTypeBFTReturns(true)
	mockChannelConfig.CapabilitiesReturns(mockChannelCapabilities)
	mockResources.ChannelConfigReturns(mockChannelConfig)

	mockNewResources := &mutableResourcesMock{
		Resources: mockResources,
	}
	mockNewResources.ValidateNewReturns(errors.New("new config is bad"))

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	require.NoError(t, err)

	cs := &ChainSupport{
		ledgerResources: &ledgerResources{
			configResources: &configResources{
				mutableResources: mockNewResources,
				bccsp:            cryptoProvider,
			},
		},
		BCCSP: cryptoProvider,
	}

	_, err = cs.ProposeConfigUpdate(&common.Envelope{})
	require.EqualError(t, err, "new config is bad")
}
