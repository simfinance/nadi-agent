package provision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "embed"
)

const (
	agentAccountName        = "nadi-agent"
	agentBinaryPath         = "/opt/nadi/bin/nadi-agent"
	agentStateDirectory     = "/var/lib/nadi"
	agentStateFile          = "/var/lib/nadi/state.json"
	agentManifestPath       = "/etc/nadi/applications.json"
	agentUnitPath           = "/etc/systemd/system/nadi-agent.service"
	brokerUnitPath          = "/etc/systemd/system/nadi-handoff-broker.service"
	activationPublicKeyPath = "/etc/nadi/keys/activation-public.pem"
	maximumArtifactBytes    = 128 << 20
	maximumHelperOutput     = 16 << 10
)

//go:embed assets/activation-public.pem
var helperActivationPublicKey []byte

//go:embed assets/nadi-agent.service
var helperAgentUnit []byte

//go:embed assets/nadi-handoff-broker.service
var helperBrokerUnit []byte

type HelperResponse struct {
	ProtocolVersion  int    `json:"protocol_version"`
	Success          bool   `json:"success"`
	Phase            string `json:"phase"`
	EnrollmentStatus string `json:"enrollment_status"`
	RetrySafe        bool   `json:"retry_safe"`
	AgentVersion     string `json:"agent_version"`
	ApplicationCount int    `json:"application_count"`
	Message          string `json:"message"`
}

type helperRuntimeIdentity struct {
	uid int
	gid int
}

func ensureNoSymlinkPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}

	current := string(os.PathSeparator)
	segments := strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator))

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		current = filepath.Join(current, segment)
		metadata, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path component: %w", err)
		}

		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
			return errors.New("path contains a symlink or non-directory component")
		}
	}

	return nil
}

func validateApplicationTargets(request ProvisionRequest) error {
	return validateApplicationTargetsAt(request, "/etc/php")
}

func validateApplicationTargetsAt(request ProvisionRequest, configurationRoot string) error {
	poolIdentities, err := readPHPFPMRuntimeIdentities(configurationRoot)
	if err != nil {
		return err
	}

	for index, application := range request.Applications {
		if err := ensureNoSymlinkPath(application.BasePath); err != nil {
			return fmt.Errorf("application %d base path is unsafe: %w", index, err)
		}

		resolvedPath, err := filepath.EvalSymlinks(application.BasePath)
		if err != nil || resolvedPath != application.BasePath {
			return fmt.Errorf("application %d base path is not canonical", index)
		}

		artisanPath := filepath.Join(application.BasePath, "artisan")
		artisanMetadata, err := os.Lstat(artisanPath)
		if err != nil || artisanMetadata.Mode()&os.ModeSymlink != 0 || !artisanMetadata.Mode().IsRegular() {
			return fmt.Errorf("application %d does not contain a regular Laravel artisan entrypoint", index)
		}

		if _, err := user.LookupId(strconv.Itoa(application.RuntimeUID)); err != nil {
			return fmt.Errorf("application %d runtime user does not exist", index)
		}
		if _, err := user.LookupGroupId(strconv.Itoa(application.RuntimeGID)); err != nil {
			return fmt.Errorf("application %d runtime group does not exist", index)
		}

		if _, exists := poolIdentities[fmt.Sprintf("%d:%d", application.RuntimeUID, application.RuntimeGID)]; !exists {
			return fmt.Errorf("application %d runtime UID/GID does not match a root-owned PHP-FPM pool", index)
		}
	}

	return nil
}

func validateRootOwnedDirectoryChain(root string, target string) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(target) {
		return errors.New("directory paths must be absolute")
	}

	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("target directory must be beneath the PHP-FPM configuration root")
	}

	current := root
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("PHP-FPM directory path contains an invalid component")
		}

		current = filepath.Join(current, segment)
		metadata, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect directory component: %w", err)
		}
		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
			return errors.New("PHP-FPM directory path contains a symlink or non-directory component")
		}

		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || metadata.Mode().Perm()&0022 != 0 {
			return errors.New("PHP-FPM directory components must be root-owned and not group/other writable")
		}
	}

	return nil
}

func readRootOwnedRegularFile(path string, maximumSize int64) ([]byte, error) {
	pathMetadata, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathMetadata.Mode()&os.ModeSymlink != 0 || !pathMetadata.Mode().IsRegular() || pathMetadata.Size() < 1 || pathMetadata.Size() > maximumSize {
		return nil, errors.New("file must be a bounded regular non-symlink file")
	}

	pathStat, ok := pathMetadata.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Uid != 0 || pathMetadata.Mode().Perm()&0022 != 0 {
		return nil, errors.New("file must be root-owned and not group/other writable")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedMetadata, err := file.Stat()
	if err != nil {
		return nil, err
	}
	openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
	if !ok ||
		openedStat.Dev != pathStat.Dev ||
		openedStat.Ino != pathStat.Ino ||
		openedStat.Uid != 0 ||
		!openedMetadata.Mode().IsRegular() ||
		openedMetadata.Mode().Perm()&0022 != 0 ||
		openedMetadata.Size() < 1 ||
		openedMetadata.Size() > maximumSize {
		return nil, errors.New("file changed during access or has unsafe metadata")
	}

	content, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) == 0 || int64(len(content)) > maximumSize {
		return nil, errors.New("file content is empty or exceeds the size limit")
	}

	return content, nil
}

func readPHPFPMRuntimeIdentities(configurationRoot string) (map[string]struct{}, error) {
	if err := ensureNoSymlinkPath(configurationRoot); err != nil {
		return nil, fmt.Errorf("PHP-FPM configuration root is unsafe: %w", err)
	}

	rootMetadata, err := os.Lstat(configurationRoot)
	if err != nil {
		return nil, err
	}
	rootStat, ok := rootMetadata.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || rootMetadata.Mode().Perm()&0022 != 0 {
		return nil, errors.New("PHP-FPM configuration root must be root-owned and not group/other writable")
	}

	poolFiles, err := filepath.Glob(filepath.Join(configurationRoot, "*", "fpm", "pool.d", "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("discover PHP-FPM pool configurations: %w", err)
	}
	if len(poolFiles) == 0 {
		return nil, errors.New("no PHP-FPM pool configuration was found")
	}

	userPattern := regexp.MustCompile("(?m)^[\\t ]*user[\\t ]*=[\\t ]*([a-zA-Z_][a-zA-Z0-9_.-]*)[\\t ]*$")
	groupPattern := regexp.MustCompile("(?m)^[\\t ]*group[\\t ]*=[\\t ]*([a-zA-Z_][a-zA-Z0-9_.-]*)[\\t ]*$")
	identities := make(map[string]struct{}, len(poolFiles))

	for _, poolPath := range poolFiles {
		if err := validateRootOwnedDirectoryChain(configurationRoot, filepath.Dir(poolPath)); err != nil {
			return nil, fmt.Errorf("PHP-FPM pool configuration directory is unsafe: %w", err)
		}

		content, err := readRootOwnedRegularFile(poolPath, 64*1024)
		if err != nil {
			return nil, fmt.Errorf("read PHP-FPM pool configuration: %w", err)
		}

		userMatch := userPattern.FindSubmatch(content)
		if len(userMatch) != 2 {
			return nil, errors.New("PHP-FPM pool configuration has no valid runtime user")
		}
		runtimeUser, err := user.Lookup(string(userMatch[1]))
		if err != nil {
			return nil, errors.New("PHP-FPM pool runtime user cannot be resolved")
		}
		uid, err := strconv.Atoi(runtimeUser.Uid)
		if err != nil || uid < 1 {
			return nil, errors.New("PHP-FPM pool runtime UID must be non-root")
		}

		gid := 0
		groupMatch := groupPattern.FindSubmatch(content)
		if len(groupMatch) == 2 {
			runtimeGroup, lookupErr := user.LookupGroup(string(groupMatch[1]))
			if lookupErr != nil {
				return nil, errors.New("PHP-FPM pool runtime group cannot be resolved")
			}
			gid, err = strconv.Atoi(runtimeGroup.Gid)
		} else {
			gid, err = strconv.Atoi(runtimeUser.Gid)
		}
		if err != nil || gid < 1 {
			return nil, errors.New("PHP-FPM pool runtime GID must be non-root")
		}

		identities[fmt.Sprintf("%d:%d", uid, gid)] = struct{}{}
	}

	return identities, nil
}

func validateStagedArtifactOwner(request ProvisionRequest) error {
	path := request.Release.ArtifactPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("staged Agent artifact path must be absolute and canonical")
	}

	var matched *ProvisionApplication

	for index := range request.Applications {
		stagingDirectory := filepath.Join(
			request.Applications[index].BasePath,
			"storage",
			"app",
			"private",
			"nadi",
			"releases",
			"staging",
		)
		if strings.HasPrefix(path, stagingDirectory+string(os.PathSeparator)) {
			if matched != nil {
				return errors.New("staged Agent artifact path ambiguously matches multiple applications")
			}
			matched = &request.Applications[index]
		}
	}

	if matched == nil {
		return errors.New("staged Agent artifact must be inside a registered Laravel application's private release staging directory")
	}

	if err := ensureNoSymlinkPath(filepath.Dir(path)); err != nil {
		return fmt.Errorf("staged Agent artifact parent path is unsafe: %w", err)
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect staged Agent artifact: %w", err)
	}

	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return errors.New("staged Agent artifact must be a regular non-symlink file")
	}

	if metadata.Size() < 1 || metadata.Size() > maximumArtifactBytes {
		return errors.New("staged Agent artifact size is outside the allowed limit")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != matched.RuntimeUID || int(stat.Gid) != matched.RuntimeGID {
		return errors.New("staged Agent artifact ownership does not match the registered Laravel runtime identity")
	}

	if metadata.Mode().Perm()&0022 != 0 {
		return errors.New("staged Agent artifact must not be group- or other-writable")
	}

	return nil
}

func rejectExistingAgentState() error {
	metadata, err := os.Lstat(agentStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing Agent state: %w", err)
	}

	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return errors.New("existing Agent state path is unsafe; automatic replacement is prohibited")
	}

	return errors.New("existing Agent state was found; use the identity-restore or repair workflow instead of a new enrollment")
}

func ensureAgentAccount() (helperRuntimeIdentity, error) {
	group, err := user.LookupGroup(agentAccountName)
	if err != nil {
		if _, runErr := runTrustedCommand("/usr/sbin/groupadd", "--system", agentAccountName); runErr != nil {
			return helperRuntimeIdentity{}, fmt.Errorf("create dedicated NADI system group: %w", runErr)
		}
		group, err = user.LookupGroup(agentAccountName)
	}
	if err != nil {
		return helperRuntimeIdentity{}, fmt.Errorf("resolve dedicated NADI system group: %w", err)
	}

	groupID, err := strconv.Atoi(group.Gid)
	if err != nil || groupID < 1 {
		return helperRuntimeIdentity{}, errors.New("dedicated NADI system group has an invalid GID")
	}

	account, err := user.Lookup(agentAccountName)
	if err != nil {
		_, runErr := runTrustedCommand(
			"/usr/sbin/useradd",
			"--system",
			"--gid", agentAccountName,
			"--home-dir", agentStateDirectory,
			"--no-create-home",
			"--shell", "/usr/sbin/nologin",
			agentAccountName,
		)
		if runErr != nil {
			return helperRuntimeIdentity{}, fmt.Errorf("create dedicated NADI system account: %w", runErr)
		}
		account, err = user.Lookup(agentAccountName)
	}
	if err != nil {
		return helperRuntimeIdentity{}, fmt.Errorf("resolve dedicated NADI system account: %w", err)
	}

	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1 || uid == 0 {
		return helperRuntimeIdentity{}, errors.New("dedicated NADI runtime UID must be non-root")
	}

	accountGID, err := strconv.Atoi(account.Gid)
	if err != nil || accountGID != groupID {
		return helperRuntimeIdentity{}, errors.New("dedicated NADI account must use its fixed primary group")
	}

	if account.HomeDir != agentStateDirectory {
		return helperRuntimeIdentity{}, errors.New("existing NADI service account has an unexpected home directory")
	}
	if err := validateAgentPasswdEntry(uid, groupID); err != nil {
		return helperRuntimeIdentity{}, err
	}
	if err := validateAgentGroupEntry(groupID); err != nil {
		return helperRuntimeIdentity{}, err
	}

	groupIDs, err := account.GroupIds()
	if err != nil {
		return helperRuntimeIdentity{}, fmt.Errorf("inspect NADI service account group memberships: %w", err)
	}
	for _, supplementaryGroupID := range groupIDs {
		if supplementaryGroupID != strconv.Itoa(groupID) {
			return helperRuntimeIdentity{}, errors.New("NADI service account must not belong to supplementary groups")
		}
	}

	return helperRuntimeIdentity{uid: uid, gid: groupID}, nil
}

func validateAgentPasswdEntry(expectedUID int, expectedGID int) error {
	content, err := readRootOwnedSystemFile("/etc/passwd", 1<<20)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != agentAccountName {
			continue
		}

		uid, uidErr := strconv.Atoi(fields[2])
		gid, gidErr := strconv.Atoi(fields[3])
		if uidErr != nil || gidErr != nil || uid != expectedUID || gid != expectedGID {
			return errors.New("NADI service account passwd identity does not match the resolved UID/GID")
		}
		if fields[5] != agentStateDirectory {
			return errors.New("NADI service account home directory does not match the fixed Agent state directory")
		}
		if fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin" {
			return errors.New("NADI service account must use a non-login shell")
		}

		return nil
	}

	return errors.New("NADI service account passwd entry is missing")
}

func validateAgentGroupEntry(expectedGID int) error {
	content, err := readRootOwnedSystemFile("/etc/group", 1<<20)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] != agentAccountName {
			continue
		}

		gid, gidErr := strconv.Atoi(fields[2])
		if gidErr != nil || gid != expectedGID {
			return errors.New("NADI service group GID does not match the resolved primary group")
		}
		if fields[3] != "" {
			return errors.New("NADI service group must not contain supplementary members")
		}

		return nil
	}

	return errors.New("NADI service group entry is missing")
}

func readRootOwnedSystemFile(path string, maximumSize int64) ([]byte, error) {
	content, err := readRootOwnedRegularFile(path, maximumSize)
	if err != nil {
		return nil, fmt.Errorf("read trusted system file %s: %w", path, err)
	}

	return content, nil
}

func prepareAgentDirectories(identity helperRuntimeIdentity) error {
	directories := []struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{path: "/opt/nadi", mode: 0755, uid: 0, gid: 0},
		{path: "/opt/nadi/bin", mode: 0755, uid: 0, gid: 0},
		{path: "/etc/nadi", mode: 0750, uid: 0, gid: 0},
		{path: "/etc/nadi/keys", mode: 0750, uid: 0, gid: 0},
		{path: "/var/lib/nadi", mode: 0700, uid: identity.uid, gid: identity.gid},
		{path: "/var/log/nadi", mode: 0750, uid: identity.uid, gid: identity.gid},
		{path: "/run/nadi", mode: 0755, uid: 0, gid: 0},
	}

	for _, directory := range directories {
		if err := ensureDirectoryTree(
			string(os.PathSeparator),
			directory.path,
			directory.mode,
			directory.uid,
			directory.gid,
		); err != nil {
			return fmt.Errorf("prepare %s: %w", directory.path, err)
		}
	}

	return nil
}

func installAgentAssets(artifactPath string, expectedDigest string) error {
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("read verified Agent artifact: %w", err)
	}
	if len(artifact) == 0 || len(artifact) > maximumArtifactBytes {
		return errors.New("verified Agent artifact size is invalid")
	}

	digest := sha256.Sum256(artifact)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return errors.New("Agent artifact changed after signature and checksum verification")
	}

	if err := installImmutableFile(agentBinaryPath, artifact, 0755, 0, 0); err != nil {
		return fmt.Errorf("install Agent binary: %w", err)
	}
	if err := installImmutableFile(activationPublicKeyPath, helperActivationPublicKey, 0644, 0, 0); err != nil {
		return fmt.Errorf("install Activation Grant public key: %w", err)
	}
	if err := installImmutableFile(agentUnitPath, helperAgentUnit, 0644, 0, 0); err != nil {
		return fmt.Errorf("install Agent systemd unit: %w", err)
	}
	if err := installImmutableFile(brokerUnitPath, helperBrokerUnit, 0644, 0, 0); err != nil {
		return fmt.Errorf("install Broker systemd unit: %w", err)
	}

	return nil
}

func installImmutableFile(path string, content []byte, mode os.FileMode, uid int, gid int) error {
	metadata, err := os.Lstat(path)
	if err == nil {
		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
			return errors.New("existing installation destination is not a regular file")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("refusing to overwrite existing file %s without an approved update operation", path)
		}
		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || metadata.Mode().Perm() != mode {
			return fmt.Errorf("existing file %s has unexpected ownership or permissions", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return writeOwnedAtomicFile(path, content, mode, uid, gid)
}

func writeEnrollmentManifest(content []byte, identity helperRuntimeIdentity) (string, func(), error) {
	if len(content) == 0 || len(content) > 32*1024 {
		return "", func() {}, errors.New("enrollment manifest size is invalid")
	}

	file, err := os.CreateTemp("/run/nadi", ".nadi-enrollment-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary enrollment manifest: %w", err)
	}

	path := file.Name()
	cleanup := func() {
		_ = os.Remove(path)
	}

	if err := file.Chmod(0640); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Chown(0, identity.gid); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}

	return path, cleanup, nil
}

func runAgentEnrollment(manifestPath string, token []byte, identity helperRuntimeIdentity) ([]byte, error) {
	defer func() {
		for index := range token {
			token[index] = 0
		}
	}()

	if len(token) == 0 {
		return nil, errors.New("enrollment token is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	command := exec.CommandContext(
		ctx,
		agentBinaryPath,
		"--enroll",
		"--manifest", manifestPath,
		"--enrollment-token-stdin",
		"--enrollment-summary-stdout",
	)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + agentStateDirectory,
		"NADI_CENTRAL_URL=https://nadi.pesantrenalirsyad.org",
		"NADI_STATE_DIR=" + agentStateDirectory,
		"NADI_ACTIVATION_PUBLIC_KEY=" + activationPublicKeyPath,
		"NADI_ACTIVATION_KEY_ID=nadi-central-2026-01",
		"NADI_AGENT_HANDOFF_SOCKET=/run/nadi/credential-handoff.sock",
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(identity.uid),
			Gid:    uint32(identity.gid),
			Groups: []uint32{uint32(identity.gid)},
		},
		Setpgid: true,
	}

	tokenInput := make([]byte, len(token)+1)
	copy(tokenInput, token)
	tokenInput[len(tokenInput)-1] = '\n'
	command.Stdin = bytes.NewReader(tokenInput)

	var stdout boundedBuffer
	var stderr boundedBuffer
	stdout.maximum = maximumHelperOutput
	stderr.maximum = 4 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr

	runErr := command.Run()
	for index := range tokenInput {
		tokenInput[index] = 0
	}

	if runErr != nil {
		if ctx.Err() != nil {
			return nil, errors.New("Agent enrollment command timed out; Central outcome is unknown")
		}
		return nil, errors.New("Agent enrollment command failed; Central outcome is unknown")
	}

	if stdout.overflow {
		return nil, errors.New("Agent enrollment summary exceeded the allowed size")
	}

	summary := append([]byte(nil), stdout.buffer.Bytes()...)
	if len(summary) == 0 {
		return nil, errors.New("Agent enrollment completed without a summary")
	}

	return summary, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (b *boundedBuffer) Write(content []byte) (int, error) {
	if b.buffer.Len()+len(content) > b.maximum {
		b.overflow = true
		return len(content), nil
	}
	return b.buffer.Write(content)
}

func activateAgentServices() error {
	if _, err := runTrustedCommand("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd units: %w", err)
	}
	if _, err := runTrustedCommand("/usr/bin/systemctl", "enable", "--now", "nadi-handoff-broker.service"); err != nil {
		return fmt.Errorf("enable and start handoff broker: %w", err)
	}
	if _, err := runTrustedCommand("/usr/bin/systemctl", "is-active", "--quiet", "nadi-handoff-broker.service"); err != nil {
		return errors.New("handoff broker did not become active")
	}
	if _, err := runTrustedCommand("/usr/bin/systemctl", "enable", "--now", "nadi-agent.service"); err != nil {
		return fmt.Errorf("enable and start Agent service: %w", err)
	}
	if _, err := runTrustedCommand("/usr/bin/systemctl", "is-active", "--quiet", "nadi-agent.service"); err != nil {
		return errors.New("Agent service did not become active")
	}

	return nil
}

func runTrustedCommand(path string, arguments ...string) ([]byte, error) {
	metadata, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("trusted system command %s is unavailable: %w", path, err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() || metadata.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("trusted system command %s has unsafe file metadata", path)
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || metadata.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("trusted system command %s must be root-owned and executable", path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("execute trusted system command %s: %w", filepath.Base(path), err)
	}

	return output, nil
}

func writeHelperResponse(writer io.Writer, response HelperResponse) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(response)
}

func safeHelperMessage(err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func decodeHelperArtifactManifest(content []byte) (ReleaseManifest, error) {
	var manifest ReleaseManifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

func encodeHelperManifestBase64(content []byte) string {
	return base64.StdEncoding.EncodeToString(content)
}
