//go:build linux

package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const linuxIsolationTable = "ntshield_isolation"
const linuxBlockTable = "ntshield_block"
const linuxPortTable = "ntshield_ports"

type linuxNetworkBackend struct {
	runner          commandRunner
	dataDir         string
	identityKeyFile string
	controlEndpoint string
}

func newNetworkContainmentBackend(options ContainmentOptions) (networkContainmentBackend, error) {
	if options.DataDir == "" || options.IdentityKeyFile == "" || options.ControlEndpoint == "" {
		return nil, errors.New("network containment requires data directory, Agent identity key, and Control Plane endpoint")
	}
	return &linuxNetworkBackend{runner: osCommandRunner{}, dataDir: options.DataDir, identityKeyFile: options.IdentityKeyFile, controlEndpoint: options.ControlEndpoint}, nil
}

func (b *linuxNetworkBackend) isolationStatePath() string {
	return filepath.Join(b.dataDir, "containment", "host-isolation.json")
}

func (b *linuxNetworkBackend) blockStatePath() string {
	return filepath.Join(b.dataDir, "containment", "firewall-block-linux.json")
}

func (b *linuxNetworkBackend) portStatePath() string {
	return filepath.Join(b.dataDir, "containment", "firewall-ports-linux.json")
}

func (b *linuxNetworkBackend) Isolate(ctx context.Context) (map[string]interface{}, error) {
	if _, err := b.runner.Run(ctx, "nft", "--version"); err != nil {
		return nil, errors.New("nftables is required for Linux host isolation")
	}
	state, stateErr := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	_, tableErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable)
	tableExists := tableErr == nil
	if tableExists && !stateExists {
		return nil, errors.New("nftables isolation table exists without signed NTAgentShield state")
	}
	if stateExists {
		if state.Data["table"] != linuxIsolationTable || state.Data["backend"] != "nftables" {
			return nil, errors.New("signed Linux isolation ownership state is invalid")
		}
		if tableExists {
			targets, err := signedStringList(state.Data["control_targets"])
			if err != nil {
				return nil, errors.New("signed Linux isolation Control Plane targets are invalid")
			}
			if err := b.verifyIsolationTable(ctx, targets); err != nil {
				return nil, err
			}
			return map[string]interface{}{"isolated": true, "already_isolated": true, "state": state.Data, "verified": true}, nil
		}
	}

	targets, err := resolveControlTargets(ctx, b.controlEndpoint)
	if err != nil {
		return nil, err
	}
	if !stateExists {
		stateData := map[string]interface{}{"backend": "nftables", "table": linuxIsolationTable, "control_targets": controlTargetStrings(targets), "dns_allowed": true}
		if err := saveSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft", stateData); err != nil {
			return nil, fmt.Errorf("persist host isolation intent: %w", err)
		}
	}
	if err := b.applyIsolationTable(ctx, targets); err != nil {
		if !stateExists {
			_ = os.Remove(b.isolationStatePath())
		}
		return nil, err
	}
	if err := b.verifyIsolationTable(ctx, controlTargetStrings(targets)); err != nil {
		return nil, err
	}
	return map[string]interface{}{"isolated": true, "backend": "nftables", "control_targets": controlTargetStrings(targets), "recovered": stateExists, "verified": true}, nil
}

func (b *linuxNetworkBackend) verifyIsolationTable(ctx context.Context, targets []string) error {
	output, err := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable)
	if err != nil {
		return fmt.Errorf("verify host isolation table: %w", err)
	}
	text := string(output)
	for _, required := range []string{"ntshield_isolation", "policy drop", "udp dport 53 accept", "tcp dport 53 accept"} {
		if !strings.Contains(text, required) {
			return errors.New("host isolation verification is missing an owned rule")
		}
	}
	for _, target := range targets {
		host, port, err := net.SplitHostPort(target)
		if err != nil || !strings.Contains(text, host) || !strings.Contains(text, "dport "+port+" accept") {
			return errors.New("host isolation verification is missing a Control Plane exception")
		}
	}
	return nil
}

func (b *linuxNetworkBackend) applyIsolationTable(ctx context.Context, targets []controlTarget) error {
	if _, err := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); err == nil {
		return nil
	}
	script := linuxIsolationScript(targets)
	if _, err := b.runner.RunInput(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("install nftables host isolation: %w", err)
	}
	return nil
}

func (b *linuxNetworkBackend) Release(ctx context.Context) (map[string]interface{}, error) {
	state, err := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft")
	if errors.Is(err, os.ErrNotExist) {
		if _, listErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); listErr == nil {
			return nil, errors.New("nftables isolation table exists without signed state; refusing blind deletion")
		}
		return map[string]interface{}{"released": true, "already_released": true}, nil
	}
	if err != nil {
		return nil, err
	}
	if state.Data["table"] != linuxIsolationTable || state.Data["backend"] != "nftables" {
		return nil, errors.New("signed Linux isolation ownership state is invalid")
	}
	if _, listErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); listErr != nil {
		if err := os.Remove(b.isolationStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return map[string]interface{}{"released": true, "already_released": true, "recovered_stale_state": true}, nil
	}
	if _, err := b.runner.Run(ctx, "nft", "delete", "table", "inet", linuxIsolationTable); err != nil {
		return nil, fmt.Errorf("delete nftables isolation table: %w", err)
	}
	if _, err := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); err == nil {
		return nil, errors.New("host isolation release verification found the owned nftables table still present")
	}
	if err := os.Remove(b.isolationStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove isolation state: %w", err)
	}
	return map[string]interface{}{"released": true, "backend": state.Data["backend"]}, nil
}

func (b *linuxNetworkBackend) Block(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	if _, err := b.runner.Run(ctx, "nft", "--version"); err != nil {
		return nil, errors.New("nftables is required for Linux firewall containment")
	}
	if _, err := b.ensureBlockTable(ctx, true); err != nil {
		return nil, err
	}
	familySet := "blocked4"
	if address.Is6() {
		familySet = "blocked6"
	}
	_, _ = b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}")
	if _, err := b.runner.Run(ctx, "nft", "add", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}"); err != nil {
		return nil, fmt.Errorf("add nftables blocked IP: %w", err)
	}
	if err := b.verifyBlock(ctx, familySet, address.String(), true); err != nil {
		return nil, err
	}
	return map[string]interface{}{"remote_ip": address.String(), "blocked": true, "backend": "nftables", "verified": true}, nil
}

func (b *linuxNetworkBackend) Unblock(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	owned, err := b.ensureBlockTable(ctx, false)
	if err != nil {
		return nil, err
	}
	if !owned {
		return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "already_unblocked": true}, nil
	}
	if err := b.verifyBlock(ctx, familySetFor(address), address.String(), true); err != nil {
		if strings.Contains(err.Error(), "requested state") {
			return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "already_unblocked": true, "verified": true}, nil
		}
		return nil, err
	}
	familySet := "blocked4"
	if address.Is6() {
		familySet = "blocked6"
	}
	if _, err := b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}"); err != nil {
		return nil, fmt.Errorf("delete nftables blocked IP: %w", err)
	}
	if err := b.verifyBlock(ctx, familySet, address.String(), false); err != nil {
		return nil, err
	}
	return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "backend": "nftables", "verified": true}, nil
}

func familySetFor(address netip.Addr) string {
	if address.Is6() {
		return "blocked6"
	}
	return "blocked4"
}

func (b *linuxNetworkBackend) verifyBlock(ctx context.Context, set, address string, expected bool) error {
	output, err := b.runner.Run(ctx, "nft", "list", "set", "inet", linuxBlockTable, set)
	if err != nil {
		return fmt.Errorf("verify owned nftables block set: %w", err)
	}
	present := nftSetContainsValue(string(output), address)
	if present != expected {
		return errors.New("nftables block verification did not match requested state")
	}
	return nil
}

func (b *linuxNetworkBackend) OpenPort(ctx context.Context, rule PortRule) (map[string]interface{}, error) {
	rules, err := b.ensurePortTable(ctx)
	if err != nil {
		return nil, err
	}
	key := linuxPortRuleKey(rule)
	already := rules[key]
	rules[key] = true
	if err := b.savePortRules(rules); err != nil {
		return nil, err
	}
	set := linuxPortSet(rule)
	port := strconv.Itoa(int(rule.Port))
	_, _ = b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxPortTable, set, "{", port, "}")
	if _, err := b.runner.Run(ctx, "nft", "add", "element", "inet", linuxPortTable, set, "{", port, "}"); err != nil {
		if !already {
			delete(rules, key)
			_ = b.savePortRules(rules)
		}
		return nil, fmt.Errorf("open owned nftables port: %w", err)
	}
	if err := b.verifyPortRule(ctx, rule, true); err != nil {
		return nil, err
	}
	return map[string]interface{}{"opened": true, "already_open": already, "protocol": rule.Protocol, "direction": rule.Direction, "port": rule.Port, "backend": "nftables", "verified": true}, nil
}

func (b *linuxNetworkBackend) ClosePort(ctx context.Context, rule PortRule) (map[string]interface{}, error) {
	rules, err := b.ensurePortTable(ctx)
	if err != nil {
		return nil, err
	}
	key := linuxPortRuleKey(rule)
	wasOpen := rules[key]
	delete(rules, key)
	if err := b.savePortRules(rules); err != nil {
		return nil, err
	}
	set := linuxPortSet(rule)
	port := strconv.Itoa(int(rule.Port))
	_, _ = b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxPortTable, set, "{", port, "}")
	if err := b.verifyPortRule(ctx, rule, false); err != nil {
		if wasOpen {
			rules[key] = true
			_ = b.savePortRules(rules)
		}
		return nil, err
	}
	return map[string]interface{}{"closed": true, "already_closed": !wasOpen, "protocol": rule.Protocol, "direction": rule.Direction, "port": rule.Port, "backend": "nftables", "verified": true}, nil
}

func (b *linuxNetworkBackend) ensurePortTable(ctx context.Context) (map[string]bool, error) {
	state, stateErr := loadSignedContainmentState(b.portStatePath(), b.identityKeyFile, "firewall-ports-linux-nft")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	_, tableErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxPortTable)
	tableExists := tableErr == nil
	if tableExists && !stateExists {
		return nil, errors.New("nftables port table exists without signed NTAgentShield ownership state")
	}
	rules := map[string]bool{}
	if stateExists {
		if state.Data["table"] != linuxPortTable || state.Data["backend"] != "nftables" {
			return nil, errors.New("signed nftables port ownership state is invalid")
		}
		values, ok := state.Data["rules"].([]interface{})
		if !ok {
			return nil, errors.New("signed nftables port rules are invalid")
		}
		for _, value := range values {
			text, ok := value.(string)
			if !ok || !validLinuxPortRuleKey(text) {
				return nil, errors.New("signed nftables port rule is invalid")
			}
			rules[text] = true
		}
	}
	if !stateExists {
		if err := b.savePortRules(rules); err != nil {
			return nil, err
		}
	}
	if !tableExists {
		if _, err := b.runner.RunInput(ctx, linuxPortTableScript(), "nft", "-f", "-"); err != nil {
			if !stateExists {
				_ = os.Remove(b.portStatePath())
			}
			return nil, fmt.Errorf("create owned nftables port table: %w", err)
		}
		for key := range rules {
			rule, _ := parseLinuxPortRuleKey(key)
			_, err := b.runner.Run(ctx, "nft", "add", "element", "inet", linuxPortTable, linuxPortSet(rule), "{", strconv.Itoa(int(rule.Port)), "}")
			if err != nil {
				return nil, fmt.Errorf("restore owned nftables port rule: %w", err)
			}
		}
	}
	return rules, nil
}

func (b *linuxNetworkBackend) savePortRules(rules map[string]bool) error {
	values := make([]string, 0, len(rules))
	for rule := range rules {
		values = append(values, rule)
	}
	sort.Strings(values)
	return saveSignedContainmentState(b.portStatePath(), b.identityKeyFile, "firewall-ports-linux-nft", map[string]interface{}{"backend": "nftables", "table": linuxPortTable, "rules": values})
}

func (b *linuxNetworkBackend) verifyPortRule(ctx context.Context, rule PortRule, expected bool) error {
	output, err := b.runner.Run(ctx, "nft", "list", "set", "inet", linuxPortTable, linuxPortSet(rule))
	if err != nil {
		return fmt.Errorf("verify owned nftables port set: %w", err)
	}
	present := nftSetContainsPort(string(output), rule.Port)
	if present != expected {
		return errors.New("nftables port verification did not match requested state")
	}
	return nil
}

func (b *linuxNetworkBackend) ensureBlockTable(ctx context.Context, create bool) (bool, error) {
	state, stateErr := loadSignedContainmentState(b.blockStatePath(), b.identityKeyFile, "firewall-block-linux-nft")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return false, stateErr
	}
	if stateExists && (state.Data["table"] != linuxBlockTable || state.Data["backend"] != "nftables") {
		return false, errors.New("signed nftables block-table ownership state is invalid")
	}
	_, tableErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxBlockTable)
	tableExists := tableErr == nil

	if tableExists && !stateExists {
		return false, errors.New("nftables block table exists without signed NTAgentShield ownership state")
	}
	if stateExists && tableExists {
		return true, nil
	}
	if stateExists && !tableExists && !create {
		if err := os.Remove(b.blockStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	if !stateExists && !create {
		return false, nil
	}

	createdState := false
	if !stateExists {
		stateData := map[string]interface{}{"backend": "nftables", "table": linuxBlockTable}
		if err := saveSignedContainmentState(b.blockStatePath(), b.identityKeyFile, "firewall-block-linux-nft", stateData); err != nil {
			return false, fmt.Errorf("persist nftables block-table ownership intent: %w", err)
		}
		createdState = true
	}
	if err := b.createBlockTable(ctx); err != nil {
		if createdState {
			_ = os.Remove(b.blockStatePath())
		}
		return false, err
	}
	return true, nil
}

func (b *linuxNetworkBackend) createBlockTable(ctx context.Context) error {
	script := `table inet ntshield_block {
    set blocked4 { type ipv4_addr; }
    set blocked6 { type ipv6_addr; }
    chain input {
        type filter hook input priority -250; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }
    chain output {
        type filter hook output priority -250; policy accept;
        ip daddr @blocked4 drop
        ip6 daddr @blocked6 drop
    }
}
`
	if _, err := b.runner.RunInput(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("create NTAgentShield nftables block table: %w", err)
	}
	return nil
}

func linuxIsolationScript(targets []controlTarget) string {
	var outputRules strings.Builder
	for _, target := range targets {
		port := strconv.Itoa(int(target.Port))
		if target.IP.Is4() {
			fmt.Fprintf(&outputRules, "        ip daddr %s tcp dport %s accept\n", target.IP.String(), port)
		} else {
			fmt.Fprintf(&outputRules, "        ip6 daddr %s tcp dport %s accept\n", target.IP.String(), port)
		}
	}
	return fmt.Sprintf(`table inet ntshield_isolation {
    chain input {
        type filter hook input priority -300; policy drop;
        iifname "lo" accept
        ct state established,related accept
        udp sport 67 udp dport 68 accept
    }
    chain output {
        type filter hook output priority -300; policy drop;
        oifname "lo" accept
        ct state established,related accept
%s        udp dport 53 accept
        tcp dport 53 accept
        udp sport 68 udp dport 67 accept
    }
}
`, outputRules.String())
}

func controlTargetStrings(targets []controlTarget) []string {
	items := make([]string, 0, len(targets))
	for _, target := range targets {
		items = append(items, target.String())
	}
	return items
}

func linuxPortRuleKey(rule PortRule) string {
	return rule.Protocol + "/" + rule.Direction + "/" + strconv.Itoa(int(rule.Port))
}

func validLinuxPortRuleKey(value string) bool {
	_, err := parseLinuxPortRuleKey(value)
	return err == nil
}

func parseLinuxPortRuleKey(value string) (PortRule, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return PortRule{}, errors.New("invalid port rule key")
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return PortRule{}, err
	}
	return normalizePortRule(parts[0], parts[1], port)
}

func linuxPortSet(rule PortRule) string {
	return strings.ToLower(rule.Protocol) + "_" + rule.Direction
}

func nftSetContainsPort(output string, port uint16) bool {
	target := strconv.Itoa(int(port))
	fields := strings.FieldsFunc(output, func(character rune) bool {
		return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '{' || character == '}' || character == ',' || character == ';'
	})
	for _, field := range fields {
		if field == target {
			return true
		}
	}
	return false
}

func nftSetContainsValue(output, target string) bool {
	fields := strings.FieldsFunc(output, func(character rune) bool {
		return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '{' || character == '}' || character == ',' || character == ';'
	})
	for _, field := range fields {
		if field == target {
			return true
		}
	}
	return false
}

func signedStringList(value interface{}) ([]string, error) {
	values, ok := value.([]interface{})
	if !ok || len(values) == 0 {
		return nil, errors.New("signed string list is missing")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, errors.New("signed string list contains an invalid value")
		}
		result = append(result, text)
	}
	return result, nil
}

func linuxPortTableScript() string {
	return `table inet ntshield_ports {
    set tcp_inbound { type inet_service; }
    set udp_inbound { type inet_service; }
    set tcp_outbound { type inet_service; }
    set udp_outbound { type inet_service; }
    chain input {
        type filter hook input priority -200; policy accept;
        tcp dport @tcp_inbound accept
        udp dport @udp_inbound accept
    }
    chain output {
        type filter hook output priority -200; policy accept;
        tcp dport @tcp_outbound accept
        udp dport @udp_outbound accept
    }
}
`
}
