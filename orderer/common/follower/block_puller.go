/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package follower

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/hyperledger/fabric/common/deliverclient"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/channel_puller.go -fake-name ChannelPuller . ChannelPuller

// ChannelPuller pulls blocks for a channel
type ChannelPuller interface {
	PullBlock(seq uint64) *common.Block
	HeightsByEndpoints() (map[string]uint64, string, error)
	UpdateEndpoints(endpoints []cluster.EndpointCriteria)
	Close()
}

// BlockPullerCreator creates a ChannelPuller on demand.
// It also maintains a link to a block signature verifier, and exposes a method to update it on incoming config blocks.
// The ChannelPuller generated by this factory always accesses the updated verifier, since it is generated
// with a link to the factory's VerifyBlockSequence method.
type BlockPullerCreator struct {
	JoinBlock               *common.Block
	channelID               string
	bccsp                   bccsp.BCCSP
	blockSigVerifierFactory cluster.VerifierFactory     // Creates a new block signature verifier
	blockSigVerifier        protoutil.BlockVerifierFunc // The current block signature verifier, from the latest channel config
	clusterConfig           localconfig.Cluster
	signer                  identity.SignerSerializer
	der                     *pem.Block
	stdDialer               *cluster.StandardDialer
	ClusterVerifyBlocks     ClusterVerifyBlocksFunc // Default: cluster.VerifyBlocks, or a mock for testing
	vb                      protoutil.VerifierBuilder
}

// ClusterVerifyBlocksFunc is a function that matches the signature of cluster.VerifyBlocks, and allows mocks for testing.
type ClusterVerifyBlocksFunc func(blockBuff []*common.Block, signatureVerifier protoutil.BlockVerifierFunc, vb protoutil.VerifierBuilder) error

// NewBlockPullerCreator creates a new BlockPullerCreator, using the configuration details that do not change during
// the life cycle of the orderer.
func NewBlockPullerCreator(
	channelID string,
	logger *flogging.FabricLogger,
	signer identity.SignerSerializer,
	baseDialer *cluster.PredicateDialer,
	clusterConfig localconfig.Cluster,
	bccsp bccsp.BCCSP,
) (*BlockPullerCreator, error) {
	stdDialer := &cluster.StandardDialer{
		Config: baseDialer.Config,
	}
	stdDialer.Config.AsyncConnect = false
	stdDialer.Config.SecOpts.VerifyCertificate = nil

	der, _ := pem.Decode(stdDialer.Config.SecOpts.Certificate)
	if der == nil {
		return nil, errors.Errorf("client certificate isn't in PEM format: %v",
			string(stdDialer.Config.SecOpts.Certificate))
	}

	factory := &BlockPullerCreator{
		channelID: channelID,
		bccsp:     bccsp,
		blockSigVerifierFactory: &deliverclient.BlockVerifierAssembler{
			Logger: logger,
			BCCSP:  bccsp,
		},
		clusterConfig:       clusterConfig,
		signer:              signer,
		stdDialer:           stdDialer,
		der:                 der,
		ClusterVerifyBlocks: cluster.VerifyBlocksBFT, // The default block sequence verification method.
		vb:                  cluster.BlockVerifierBuilder(bccsp),
	}

	return factory, nil
}

// BlockPuller creates a block puller on demand, taking the endpoints from the config block.
func (creator *BlockPullerCreator) BlockPuller(configBlock *common.Block, stopChannel chan struct{}) (ChannelPuller, error) {
	// Extract the TLS CA certs and endpoints from the join-block
	endpoints, err := cluster.EndpointconfigFromConfigBlock(configBlock, creator.bccsp)
	if err != nil {
		return nil, errors.WithMessage(err, "error extracting endpoints from config block")
	}

	logger := flogging.MustGetLogger("orderer.common.cluster.puller").With("channel", creator.channelID)

	creator.JoinBlock = configBlock

	myCert, err := x509.ParseCertificate(creator.der.Bytes)
	if err != nil {
		logger.Warnf("Failed parsing my own TLS certificate: %v, therefore we may connect to our own endpoint when pulling blocks", err)
	}

	bp := &cluster.BlockPuller{
		MyOwnTLSCert:        myCert,
		VerifyBlockSequence: creator.VerifyBlockSequence,
		Logger:              logger,
		RetryTimeout:        creator.clusterConfig.ReplicationRetryTimeout,
		MaxTotalBufferBytes: creator.clusterConfig.ReplicationBufferSize,
		MaxPullBlockRetries: uint64(creator.clusterConfig.ReplicationMaxRetries),
		FetchTimeout:        creator.clusterConfig.ReplicationPullTimeout,
		Endpoints:           endpoints,
		Signer:              creator.signer,
		TLSCert:             creator.der.Bytes,
		Channel:             creator.channelID,
		Dialer:              creator.stdDialer,
		StopChannel:         stopChannel,
	}

	return bp, nil
}

// UpdateVerifierFromConfigBlock creates a new block signature verifier from the config block and updates the internal
// link to said verifier.
func (creator *BlockPullerCreator) UpdateVerifierFromConfigBlock(configBlock *common.Block) error {
	configEnv, err := deliverclient.ConfigFromBlock(configBlock)
	if err != nil {
		return errors.WithMessage(err, "failed to extract config envelope from block")
	}
	verifier, err := creator.blockSigVerifierFactory.VerifierFromConfig(configEnv, creator.channelID)
	if err != nil {
		return errors.WithMessage(err, "failed to construct a block signature verifier from config envelope")
	}
	creator.blockSigVerifier = verifier
	return nil
}

// VerifyBlockSequence verifies a sequence of blocks, using the internal block signature verifier. It also bootstraps
// the block sig verifier form the genesis block if it does not exist, and skips verifying the genesis block.
func (creator *BlockPullerCreator) VerifyBlockSequence(blocks []*common.Block, _ string) error {
	if len(blocks) == 0 {
		return errors.New("buffer is empty")
	}
	if blocks[0] == nil {
		return errors.New("first block is nil")
	}
	if blocks[0].Header == nil {
		return errors.New("first block header is nil")
	}
	if blocks[0].Header.Number == 0 {
		if creator.JoinBlock != nil && creator.JoinBlock.Header.Number == 0 {
			// If we have joined with a genesis block,
			// replace the genesis block we got from the network
			// with our own.
			blocks[0] = creator.JoinBlock
		}
		configEnv, err := deliverclient.ConfigFromBlock(blocks[0])
		if err != nil {
			return errors.WithMessage(err, "failed to extract config envelope from genesis block")
		}
		// Bootstrap the verifier from the genesis block, as it will be used to verify
		// the subsequent blocks in the batch.
		creator.blockSigVerifier, err = creator.blockSigVerifierFactory.VerifierFromConfig(configEnv, creator.channelID)
		if err != nil {
			return errors.WithMessage(err, "failed to construct a block signature verifier from genesis block")
		}
		blocksAfterGenesis := blocks[1:]
		if len(blocksAfterGenesis) == 0 {
			return nil
		}
		// TODO: we should revisit this as in theory a malicious node can give an incorrect genesis block.
		// However, if that happens, then the onboarding node would deviate from the correct nodes and it will be detected by us
		// due to follower chain comparing the block it is joined with with the block it pulled by doing:
		// if c.joinBlock != nil && !proto.Equal(c.ledgerResources.Block(c.joinBlock.Header.Number).Data, c.joinBlock.Data) {
		//	c.logger.Panicf("Join block (%d) we pulled mismatches block we joined with", c.joinBlock.Header.Number)
		// }
		return creator.ClusterVerifyBlocks(blocksAfterGenesis, creator.blockSigVerifier, creator.vb)
	}

	if creator.blockSigVerifier == nil {
		return errors.New("nil block signature verifier")
	}

	return creator.ClusterVerifyBlocks(blocks, creator.blockSigVerifier, creator.vb)
}
