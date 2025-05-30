/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-config/protolator/protoext/ordererext"
	"github.com/hyperledger/fabric-config/protolator/protoext/peerext"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/configtxgen/encoder"
	"github.com/hyperledger/fabric/internal/configtxgen/genesisconfig"
	"github.com/hyperledger/fabric/internal/configtxgen/metadata"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

var logger = flogging.MustGetLogger("common.tools.configtxgen")

func doOutputBlock(config *genesisconfig.Profile, channelID string, outputBlock string) error {
	pgen, err := encoder.NewBootstrapper(config)
	if err != nil {
		return errors.WithMessage(err, "could not create bootstrapper")
	}
	logger.Info("Generating genesis block")
	if config.Orderer == nil {
		return errors.New("refusing to generate block which is missing orderer section")
	}
	if config.Consortiums != nil {
		logger.Error("Warning: 'Consortiums' should be nil since system channel is no longer supported in Fabric v3.x")
	} else {
		if config.Application == nil {
			return errors.New("refusing to generate application channel block which is missing application section")
		}
		logger.Info("Creating application channel genesis block")
	}
	genesisBlock := pgen.GenesisBlockForChannel(channelID)
	logger.Info("Writing genesis block")
	err = writeFile(outputBlock, protoutil.MarshalOrPanic(genesisBlock), 0o640)
	if err != nil {
		return fmt.Errorf("error writing genesis block: %s", err)
	}
	return nil
}

func doOutputChannelCreateTx(conf, baseProfile *genesisconfig.Profile, channelID string, outputChannelCreateTx string) error {
	logger.Info("Generating new channel configtx")

	var configtx *cb.Envelope
	var err error
	if baseProfile == nil {
		configtx, err = encoder.MakeChannelCreationTransaction(channelID, nil, conf)
	} else {
		configtx, err = encoder.MakeChannelCreationTransactionWithSystemChannelContext(channelID, nil, conf, baseProfile)
	}
	if err != nil {
		return err
	}

	logger.Info("Writing new channel tx")
	err = writeFile(outputChannelCreateTx, protoutil.MarshalOrPanic(configtx), 0o640)
	if err != nil {
		return fmt.Errorf("error writing channel create tx: %s", err)
	}
	return nil
}

func doInspectBlock(inspectBlock string) error {
	logger.Info("Inspecting block")
	data, err := os.ReadFile(inspectBlock)
	if err != nil {
		return fmt.Errorf("could not read block %s", inspectBlock)
	}

	logger.Info("Parsing genesis block")
	block, err := protoutil.UnmarshalBlock(data)
	if err != nil {
		return fmt.Errorf("error unmarshalling to block: %s", err)
	}
	err = protolator.DeepMarshalJSON(os.Stdout, block)
	if err != nil {
		return fmt.Errorf("malformed block contents: %s", err)
	}
	return nil
}

func doInspectChannelCreateTx(inspectChannelCreateTx string) error {
	logger.Info("Inspecting transaction")
	data, err := os.ReadFile(inspectChannelCreateTx)
	if err != nil {
		return fmt.Errorf("could not read channel create tx: %s", err)
	}

	logger.Info("Parsing transaction")
	env, err := protoutil.UnmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("Error unmarshalling envelope: %s", err)
	}

	err = protolator.DeepMarshalJSON(os.Stdout, env)
	if err != nil {
		return fmt.Errorf("malformed transaction contents: %s", err)
	}

	return nil
}

func doPrintOrg(t *genesisconfig.TopLevel, printOrg string) error {
	for _, org := range t.Organizations {
		if org.Name == printOrg {
			if len(org.OrdererEndpoints) > 0 {
				// An Orderer OrgGroup
				channelCapabilities := t.Capabilities["Channel"]
				og, err := encoder.NewOrdererOrgGroup(org, channelCapabilities)
				if err != nil {
					return errors.Wrapf(err, "bad org definition for org %s", org.Name)
				}

				if err := protolator.DeepMarshalJSON(os.Stdout, &ordererext.DynamicOrdererOrgGroup{ConfigGroup: og}); err != nil {
					return errors.Wrapf(err, "malformed org definition for org: %s", org.Name)
				}
				return nil
			}

			// Otherwise assume it is an Application OrgGroup, where the encoder is not strict whether anchor peers exist or not
			ag, err := encoder.NewApplicationOrgGroup(org)
			if err != nil {
				return errors.Wrapf(err, "bad org definition for org %s", org.Name)
			}
			if err := protolator.DeepMarshalJSON(os.Stdout, &peerext.DynamicApplicationOrgGroup{ConfigGroup: ag}); err != nil {
				return errors.Wrapf(err, "malformed org definition for org: %s", org.Name)
			}
			return nil
		}
	}
	return errors.Errorf("organization %s not found", printOrg)
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	dirPath := filepath.Dir(filename)
	exists, err := dirExists(dirPath)
	if err != nil {
		return err
	}
	if !exists {
		err = os.MkdirAll(dirPath, 0o750)
		if err != nil {
			return err
		}
	}
	return os.WriteFile(filename, data, perm)
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func main() {
	var outputBlock, outputChannelCreateTx, channelCreateTxBaseProfile, profile, configPath, channelID, inspectBlock, inspectChannelCreateTx, asOrg, printOrg string

	flag.StringVar(&outputBlock, "outputBlock", "", "The path to write the genesis block to (if set)")
	flag.StringVar(&channelID, "channelID", "", "The channel ID to use in the configtx")
	flag.StringVar(&outputChannelCreateTx, "outputCreateChannelTx", "", "[DEPRECATED] The path to write a channel creation configtx to (if set)")
	flag.StringVar(&channelCreateTxBaseProfile, "channelCreateTxBaseProfile", "", "[DEPRECATED] Specifies a profile to consider as the orderer system channel current state to allow modification of non-application parameters during channel create tx generation. Only valid in conjunction with 'outputCreateChannelTx'.")
	flag.StringVar(&profile, "profile", "", "The profile from configtx.yaml to use for generation.")
	flag.StringVar(&configPath, "configPath", "", "The path containing the configuration to use (if set)")
	flag.StringVar(&inspectBlock, "inspectBlock", "", "Prints the configuration contained in the block at the specified path")
	flag.StringVar(&inspectChannelCreateTx, "inspectChannelCreateTx", "", "[DEPRECATED] Prints the configuration contained in the transaction at the specified path")
	flag.StringVar(&asOrg, "asOrg", "", "Performs the config generation as a particular organization (by name), only including values in the write set that org (likely) has privilege to set")
	flag.StringVar(&printOrg, "printOrg", "", "Prints the definition of an organization as JSON. (useful for adding an org to a channel manually)")

	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if channelID == "" && (outputBlock != "" || outputChannelCreateTx != "") {
		logger.Fatalf("Missing channelID, please specify it with '-channelID'")
	}

	// show version
	if *version {
		printVersion()
		os.Exit(0)
	}

	// don't need to panic when running via command line
	defer func() {
		if err := recover(); err != nil {
			if strings.Contains(fmt.Sprint(err), "Error reading configuration: Unsupported Config Type") {
				logger.Error("Could not find configtx.yaml. " +
					"Please make sure that FABRIC_CFG_PATH or -configPath is set to a path " +
					"which contains configtx.yaml")
				os.Exit(1)
			}
			if strings.Contains(fmt.Sprint(err), "Could not find profile") {
				logger.Error(fmt.Sprint(err) + ". " +
					"Please make sure that FABRIC_CFG_PATH or -configPath is set to a path " +
					"which contains configtx.yaml with the specified profile")
				os.Exit(1)
			}
			logger.Panic(err)
		}
	}()

	logger.Info("Loading configuration")
	err := factory.InitFactories(nil)
	if err != nil {
		logger.Fatalf("Error on initFactories: %s", err)
	}
	var profileConfig *genesisconfig.Profile
	if outputBlock != "" || outputChannelCreateTx != "" {
		if profile == "" {
			logger.Fatalf("The '-profile' is required when '-outputBlock', '-outputChannelCreateTx' is specified")
		}

		if configPath != "" {
			profileConfig = genesisconfig.Load(profile, configPath)
		} else {
			profileConfig = genesisconfig.Load(profile)
		}
	}

	var baseProfile *genesisconfig.Profile
	if channelCreateTxBaseProfile != "" {
		if outputChannelCreateTx == "" {
			logger.Warning("Specified 'channelCreateTxBaseProfile', but did not specify 'outputChannelCreateTx', 'channelCreateTxBaseProfile' will not affect output.")
		}
		if configPath != "" {
			baseProfile = genesisconfig.Load(channelCreateTxBaseProfile, configPath)
		} else {
			baseProfile = genesisconfig.Load(channelCreateTxBaseProfile)
		}
	}

	if outputBlock != "" {
		if err := doOutputBlock(profileConfig, channelID, outputBlock); err != nil {
			logger.Fatalf("Error on outputBlock: %s", err)
		}
	}

	if outputChannelCreateTx != "" {
		if err := doOutputChannelCreateTx(profileConfig, baseProfile, channelID, outputChannelCreateTx); err != nil {
			logger.Fatalf("Error on outputChannelCreateTx: %s", err)
		}
	}

	if inspectBlock != "" {
		if err := doInspectBlock(inspectBlock); err != nil {
			logger.Fatalf("Error on inspectBlock: %s", err)
		}
	}

	if inspectChannelCreateTx != "" {
		if err := doInspectChannelCreateTx(inspectChannelCreateTx); err != nil {
			logger.Fatalf("Error on inspectChannelCreateTx: %s", err)
		}
	}

	if printOrg != "" {
		var topLevelConfig *genesisconfig.TopLevel
		if configPath != "" {
			topLevelConfig = genesisconfig.LoadTopLevel(configPath)
		} else {
			topLevelConfig = genesisconfig.LoadTopLevel()
		}

		if err := doPrintOrg(topLevelConfig, printOrg); err != nil {
			logger.Fatalf("Error on printOrg: %s", err)
		}
	}
}

func printVersion() {
	fmt.Println(metadata.GetVersionInfo())
}
