package iptables

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
)

const kube2iamIptableChain = "PREROUTING_KUBE2IAM"

// ClearRules clear the kube2iam iptable chain and kube2iam.
func ClearRules(metadataAddress, hostInterface string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	err = ipt.Delete(
		"nat", "PREROUTING", "-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", kube2iamIptableChain, "-i", hostInterface,
	)
	if err != nil {
		// This will always fail on standard startup.
		log.WithField("chain", "PREROUTING").WithError(err).Debug("failed to remove kube2iam jump rule")
	}

	log.WithField("chain", kube2iamIptableChain).Info("Clearing kube2iam iptable chain")
	return ipt.ClearChain("nat", kube2iamIptableChain)
}

// ClearChain remove the kube2iam iptable chain and Jump rules.
func ClearChain(metadataAddress, hostInterface string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	if err = ClearRules(metadataAddress, hostInterface); err != nil {
		return err
	}
	log.WithField("chain", kube2iamIptableChain).Debug("Removing kube2iam iptable chain")
	return ipt.DeleteChain("nat", kube2iamIptableChain)
}

// AddRules adds the required rule to the host's nat table.
func AddRules(appPort int, metadataAddress, hostInterface, bindIP string) error {
	dstAddr := fmt.Sprintf("%s:%d", bindIP, appPort)
	if err := checkInterfaceExists(hostInterface); err != nil {
		return err
	}

	if bindIP == "0.0.0.0" {
		return errors.New("iptables can't redirect to 0.0.0.0")
	}

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	log.WithField("chain", kube2iamIptableChain).Debug("Adding kube2iam iptable jump rule")
	err = ipt.AppendUnique(
		"nat", "PREROUTING", "-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", kube2iamIptableChain, "-i", hostInterface,
	)
	if err != nil {
		return err
	}

	log.WithField("chain", kube2iamIptableChain).Debug("Adding kube2iam iptable chain rule")
	return ipt.AppendUnique(
		"nat", kube2iamIptableChain, "-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", "DNAT", "--to-destination", dstAddr, "-i", hostInterface,
	)
}

// checkInterfaceExists validates the interface passed exists for the given system.
// checkInterfaceExists ignores wildcard networks.
func checkInterfaceExists(hostInterface string) error {

	if strings.Contains(hostInterface, "+") {
		// wildcard networks ignored
		return nil
	}

	_, err := net.InterfaceByName(hostInterface)
	return err
}
