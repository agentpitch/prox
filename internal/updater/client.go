package updater

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var canonicalReleaseTag = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)

const (
	defaultReleasesURL = "https://api.github.com/repos/agentpitch/prox/releases?per_page=20&page=1"
	githubAPIVersion   = "2026-03-10"
	executableName     = "pitchProx.exe"
	checksumsName      = "pitchProx-windows-amd64.sha256"
	manifestName       = "pitchProx-build-manifest.json"
	archiveName        = "pitchProx-windows-amd64.zip"
	maxReleaseJSON     = int64(2 << 20)
	maxChecksumBytes   = int64(64 << 10)
	maxManifestBytes   = int64(1 << 20)
	maxExecutableBytes = int64(64 << 20)
	maxArchiveBytes    = int64(128 << 20)
	maxRuntimeBytes    = int64(16 << 20)
	maxReleaseAssets   = 32
	maxReleaseResults  = 20
)

// Source is deliberately small so update discovery and staging can be tested
// without touching the running executable or making network requests.
type Source interface {
	ListReleases(context.Context) ([]Release, error)
	Stage(context.Context, Release, string, func(downloaded, total int64)) error
}

type ClientOptions struct {
	ReleasesURL string
	HTTPClient  *http.Client
	AllowHTTP   bool // tests only
}

type GitHubClient struct {
	releasesURL *url.URL
	httpClient  *http.Client
	allowHTTP   bool
}

func NewGitHubClient(options ClientOptions) (*GitHubClient, error) {
	rawURL := strings.TrimSpace(options.ReleasesURL)
	if rawURL == "" {
		rawURL = defaultReleasesURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse releases URL: %w", err)
	}
	if err := validateRemoteURL(parsed, options.AllowHTTP, parsed.Hostname()); err != nil {
		return nil, err
	}
	base := options.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 5 * time.Minute}
	}
	clone := *base
	previousRedirect := clone.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many update download redirects")
		}
		if err := validateRemoteURL(req.URL, options.AllowHTTP, parsed.Hostname()); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}
	return &GitHubClient{releasesURL: parsed, httpClient: &clone, allowHTTP: options.AllowHTTP}, nil
}

type githubRelease struct {
	ID          int64         `json:"id"`
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	HTMLURL     string        `json:"html_url"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	State       string `json:"state"`
	Size        int64  `json:"size"`
	Digest      string `json:"digest"`
	ContentType string `json:"content_type"`
}

func (c *GitHubClient) ListReleases(ctx context.Context) ([]Release, error) {
	body, err := c.getBytes(ctx, c.releasesURL.String(), "application/vnd.github+json", maxReleaseJSON, 0, "release list")
	if err != nil {
		return nil, err
	}
	var response []githubRelease
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode GitHub release list: %w", err)
	}
	releases := make([]Release, 0, 5)
	for _, item := range response {
		if item.Draft || strings.TrimSpace(item.TagName) == "" || item.PublishedAt.IsZero() {
			continue
		}
		release := Release{
			Version:     strings.TrimSpace(item.TagName),
			Name:        strings.TrimSpace(item.Name),
			PublishedAt: item.PublishedAt.UTC(),
			Prerelease:  item.Prerelease,
			PageURL:     item.HTMLURL,
			id:          item.ID,
		}
		if release.Name == "" {
			release.Name = release.Version
		}
		assetCounts := map[string]int{}
		if len(item.Assets) > maxReleaseAssets {
			release.Reason = "в релизе слишком много файлов"
			releases = append(releases, release)
			continue
		}
		for _, rawAsset := range item.Assets {
			assetCounts[rawAsset.Name]++
			parsedAsset := asset{
				ID: rawAsset.ID, Name: rawAsset.Name, APIURL: c.assetURL(rawAsset.ID),
				Size: rawAsset.Size, Digest: strings.ToLower(strings.TrimSpace(rawAsset.Digest)),
				State: rawAsset.State, ContentType: rawAsset.ContentType,
			}
			switch rawAsset.Name {
			case executableName:
				release.executable = parsedAsset
			case archiveName:
				release.archive = parsedAsset
			case checksumsName:
				release.checksums = parsedAsset
			case manifestName:
				release.manifest = parsedAsset
			}
		}
		release.Size = release.executable.Size
		release.Installable, release.Verification, release.Reason = validateReleaseMetadata(release, assetCounts)
		if parsed, ok := parseVersion(release.Version); ok && (len(parsed.pre) > 0) != release.Prerelease {
			release.Installable = false
			release.Verification = ""
			release.Reason = "признак prerelease не соответствует версии"
		}
		releases = append(releases, release)
	}
	sort.SliceStable(releases, func(i, j int) bool {
		if releases[i].PublishedAt.Equal(releases[j].PublishedAt) {
			return releases[i].id > releases[j].id
		}
		return releases[i].PublishedAt.After(releases[j].PublishedAt)
	})
	if len(releases) > maxReleaseResults {
		releases = releases[:maxReleaseResults]
	}
	if releases == nil {
		releases = []Release{}
	}
	return releases, nil
}

func validateReleaseMetadata(release Release, counts map[string]int) (bool, string, string) {
	if !canonicalReleaseTag.MatchString(release.Version) {
		return false, "", "неподдерживаемый формат версии"
	}
	for _, name := range []string{executableName, checksumsName} {
		if counts[name] != 1 {
			return false, "", "не найден единственный обязательный файл " + name
		}
	}
	if counts[manifestName] > 1 {
		return false, "", "файл манифеста опубликован более одного раза"
	}
	for _, entry := range []asset{release.executable, release.checksums} {
		if err := validateAssetMetadata(entry); err != nil {
			return false, "", err.Error()
		}
	}
	if release.executable.Size <= 0 || release.executable.Size > maxExecutableBytes {
		return false, "", "недопустимый размер исполняемого файла"
	}
	if release.checksums.Size <= 0 || release.checksums.Size > maxChecksumBytes {
		return false, "", "недопустимый размер файла контрольных сумм"
	}
	if release.manifest.Name != "" {
		if err := validateAssetMetadata(release.manifest); err != nil {
			return false, "", err.Error()
		}
		if release.manifest.Size <= 0 || release.manifest.Size > maxManifestBytes {
			return false, "", "недопустимый размер манифеста"
		}
		return true, "manifest", ""
	}
	if comparison, known := compareVersions(release.Version, "v0.42"); known && comparison >= 0 {
		return false, "", "в релизе отсутствует обязательный манифест сборки"
	}
	if counts[archiveName] != 1 {
		return false, "", "для старого релиза не найден единственный полный пакет"
	}
	if err := validateAssetMetadata(release.archive); err != nil {
		return false, "", err.Error()
	}
	if release.archive.Size <= 0 || release.archive.Size > maxArchiveBytes {
		return false, "", "недопустимый размер полного пакета"
	}
	return true, "legacy", "старый формат: SHA-256 сверяется с метаданными GitHub и checksum-файлом, но манифеста сборки нет"
}

func validateAssetMetadata(item asset) error {
	if item.State != "uploaded" {
		return fmt.Errorf("файл %s не готов к загрузке", item.Name)
	}
	if item.ID <= 0 || strings.TrimSpace(item.APIURL) == "" {
		return fmt.Errorf("файл %s имеет неполные метаданные", item.Name)
	}
	if _, err := parseSHA256Digest(item.Digest); err != nil {
		return fmt.Errorf("файл %s: %w", item.Name, err)
	}
	return nil
}

func (c *GitHubClient) Stage(ctx context.Context, release Release, destination string, progress func(downloaded, total int64)) error {
	if !release.Installable {
		return fmt.Errorf("release %s cannot be installed: %s", release.Version, release.Reason)
	}
	checksumBytes, err := c.downloadVerifiedBytes(ctx, release.checksums, maxChecksumBytes, "checksum file")
	if err != nil {
		return err
	}
	wantExecutable, err := checksumFor(checksumBytes, executableName)
	if err != nil {
		return err
	}
	assetDigest, err := parseSHA256Digest(release.executable.Digest)
	if err != nil {
		return err
	}
	if !strings.EqualFold(wantExecutable, assetDigest) {
		return errors.New("executable SHA-256 differs between GitHub metadata and checksum file")
	}
	if release.manifest.Name != "" {
		wantManifest, err := checksumFor(checksumBytes, manifestName)
		if err != nil {
			return err
		}
		manifestDigest, err := parseSHA256Digest(release.manifest.Digest)
		if err != nil {
			return err
		}
		if !strings.EqualFold(wantManifest, manifestDigest) {
			return errors.New("manifest SHA-256 differs between GitHub metadata and checksum file")
		}
		manifestBytes, err := c.downloadVerifiedBytes(ctx, release.manifest, maxManifestBytes, "build manifest")
		if err != nil {
			return err
		}
		if err := validateBuildManifest(manifestBytes, release, wantExecutable, filepath.Dir(destination)); err != nil {
			return err
		}
	} else {
		if err := c.verifyLegacyRuntime(ctx, release, checksumBytes, destination); err != nil {
			return err
		}
	}
	return c.downloadExecutable(ctx, release.executable, destination, wantExecutable, progress)
}

func (c *GitHubClient) verifyLegacyRuntime(ctx context.Context, release Release, checksums []byte, destination string) error {
	wantArchive, err := checksumFor(checksums, archiveName)
	if err != nil {
		return err
	}
	assetDigest, err := parseSHA256Digest(release.archive.Digest)
	if err != nil {
		return err
	}
	if !strings.EqualFold(wantArchive, assetDigest) {
		return errors.New("archive SHA-256 differs between GitHub metadata and checksum file")
	}
	archivePath := destination + ".runtime.zip"
	_ = os.Remove(archivePath)
	_ = os.Remove(archivePath + ".part")
	defer os.Remove(archivePath)
	if err := c.downloadAssetFile(ctx, release.archive, archivePath, wantArchive, maxArchiveBytes, "legacy runtime package", nil); err != nil {
		return fmt.Errorf("verify legacy runtime package: %w", err)
	}
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open legacy runtime package: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > 1000 {
		return errors.New("legacy runtime package contains too many files")
	}
	entries := map[string]*zip.File{}
	for _, entry := range reader.File {
		if entry.Name != "WinDivert.dll" && entry.Name != "WinDivert64.sys" {
			continue
		}
		if entries[entry.Name] != nil {
			return fmt.Errorf("legacy runtime package contains duplicate %s", entry.Name)
		}
		if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > uint64(maxRuntimeBytes) {
			return fmt.Errorf("legacy runtime package has an invalid %s size", entry.Name)
		}
		entries[entry.Name] = entry
	}
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		entry := entries[name]
		if entry == nil {
			return fmt.Errorf("legacy runtime package has no %s", name)
		}
		archiveHash, err := hashZipEntry(entry)
		if err != nil {
			return err
		}
		installedHash, err := hashFile(filepath.Join(filepath.Dir(destination), name))
		if err != nil {
			return fmt.Errorf("hash installed %s: %w", name, err)
		}
		if !strings.EqualFold(archiveHash, installedHash) {
			return fmt.Errorf("installed %s differs from the selected legacy release; install the full package manually", name)
		}
	}
	return nil
}

func hashZipEntry(entry *zip.File) (string, error) {
	reader, err := entry.Open()
	if err != nil {
		return "", err
	}
	defer reader.Close()
	hash := sha256.New()
	written, err := io.CopyBuffer(hash, io.LimitReader(reader, maxRuntimeBytes+1), make([]byte, 64<<10))
	if err != nil {
		return "", err
	}
	if written != int64(entry.UncompressedSize64) || written > maxRuntimeBytes {
		return "", errors.New("legacy runtime package entry exceeds its declared size")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (c *GitHubClient) downloadVerifiedBytes(ctx context.Context, item asset, limit int64, description string) ([]byte, error) {
	want, err := parseSHA256Digest(item.Digest)
	if err != nil {
		return nil, fmt.Errorf("%s digest: %w", description, err)
	}
	body, err := c.getBytes(ctx, item.APIURL, "application/octet-stream", limit, item.Size, description)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%s SHA-256 does not match GitHub metadata", description)
	}
	return body, nil
}

func (c *GitHubClient) getBytes(ctx context.Context, rawURL, accept string, limit, expectedSize int64, description string) ([]byte, error) {
	request, err := c.newRequest(ctx, rawURL, accept)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", description, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, githubStatusError(response, description)
	}
	if expectedSize > 0 && response.ContentLength > 0 && response.ContentLength != expectedSize {
		return nil, fmt.Errorf("%s size differs from GitHub metadata", description)
	}
	reader := io.LimitReader(response.Body, limit+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", description, limit)
	}
	if expectedSize > 0 && int64(len(body)) != expectedSize {
		return nil, fmt.Errorf("%s size differs from GitHub metadata", description)
	}
	return body, nil
}

func (c *GitHubClient) downloadExecutable(ctx context.Context, item asset, destination, wantHash string, progress func(int64, int64)) error {
	if err := c.downloadAssetFile(ctx, item, destination, wantHash, maxExecutableBytes, "executable", progress); err != nil {
		return err
	}
	peFile, err := pe.Open(destination)
	if err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("staged executable is not a valid PE file: %w", err)
	}
	machine := peFile.FileHeader.Machine
	_ = peFile.Close()
	if machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		_ = os.Remove(destination)
		return fmt.Errorf("staged executable machine is %#x; expected AMD64", machine)
	}
	return nil
}

func (c *GitHubClient) downloadAssetFile(ctx context.Context, item asset, destination, wantHash string, limit int64, description string, progress func(int64, int64)) error {
	if !filepath.IsAbs(destination) {
		return errors.New("staged asset path must be absolute")
	}
	if item.Size <= 0 || item.Size > limit {
		return fmt.Errorf("invalid %s size", description)
	}
	request, err := c.newRequest(ctx, item.APIURL, "application/octet-stream")
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("download %s: %w", description, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubStatusError(response, description)
	}
	if response.ContentLength > 0 && response.ContentLength != item.Size {
		return fmt.Errorf("%s size differs from GitHub metadata", description)
	}
	partPath := destination + ".part"
	file, err := os.OpenFile(partPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create staged executable: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(partPath)
		}
	}()
	hash := sha256.New()
	writer := io.MultiWriter(file, hash)
	buffer := make([]byte, 64<<10)
	limited := &io.LimitedReader{R: response.Body, N: limit + 1}
	var written int64
	for {
		count, readErr := limited.Read(buffer)
		if count > 0 {
			n, writeErr := writer.Write(buffer[:count])
			written += int64(n)
			if writeErr != nil {
				return fmt.Errorf("write staged executable: %w", writeErr)
			}
			if n != count {
				return io.ErrShortWrite
			}
			if progress != nil {
				progress(written, item.Size)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read executable: %w", readErr)
		}
	}
	if written != item.Size {
		return fmt.Errorf("%s size is %d bytes; expected %d", description, written, item.Size)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(got, wantHash) {
		return fmt.Errorf("%s SHA-256 verification failed", description)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged executable: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged executable: %w", err)
	}
	if err := os.Rename(partPath, destination); err != nil {
		return fmt.Errorf("finalize staged executable: %w", err)
	}
	keep = true
	return nil
}

func (c *GitHubClient) assetURL(id int64) string {
	base := *c.releasesURL
	base.RawQuery = ""
	base.Fragment = ""
	base.Path = "/repos/agentpitch/prox/releases/assets/" + strconv.FormatInt(id, 10)
	return base.String()
}

func (c *GitHubClient) newRequest(ctx context.Context, rawURL, accept string) (*http.Request, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse update URL: %w", err)
	}
	if err := validateRemoteURL(parsed, c.allowHTTP, c.releasesURL.Hostname()); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	request.Header.Set("User-Agent", "pitchProx-updater")
	return request, nil
}

func validateRemoteURL(value *url.URL, allowHTTP bool, apiHost string) error {
	if value == nil || value.User != nil || value.Hostname() == "" {
		return errors.New("invalid update URL")
	}
	if value.Scheme != "https" && !(allowHTTP && value.Scheme == "http") {
		return errors.New("update URL must use HTTPS")
	}
	if !allowHTTP && value.Port() != "" {
		return errors.New("update URL must not contain a custom port")
	}
	host := strings.ToLower(value.Hostname())
	allowed := host == strings.ToLower(apiHost) || host == "api.github.com" || host == "github.com" || strings.HasSuffix(host, ".githubusercontent.com")
	if !allowed {
		return fmt.Errorf("update URL host %q is not allowed", host)
	}
	return nil
}

func githubStatusError(response *http.Response, description string) error {
	message := fmt.Sprintf("GitHub returned HTTP %d for %s", response.StatusCode, description)
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
		if reset := response.Header.Get("X-RateLimit-Reset"); reset != "" {
			if seconds, err := strconv.ParseInt(reset, 10, 64); err == nil {
				message += "; rate limit resets at " + time.Unix(seconds, 0).Local().Format(time.RFC3339)
			}
		}
	}
	return errors.New(message)
}

func parseSHA256Digest(value string) (string, error) {
	algorithm, digest, found := strings.Cut(strings.TrimSpace(value), ":")
	if !found || !strings.EqualFold(algorithm, "sha256") || len(digest) != 64 {
		return "", errors.New("missing or invalid SHA-256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", errors.New("missing or invalid SHA-256 digest")
	}
	return strings.ToLower(digest), nil
}

func checksumFor(content []byte, filename string) (string, error) {
	allowed := map[string]bool{
		executableName:                true,
		"pitchProx-windows-amd64.zip": true,
		manifestName:                  true,
	}
	foundEntries := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return "", errors.New("invalid checksum file format")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if !allowed[name] || strings.ContainsAny(name, `/\\`) {
			return "", fmt.Errorf("checksum file contains unexpected file %q", name)
		}
		if _, exists := foundEntries[name]; exists {
			return "", fmt.Errorf("checksum file contains duplicate %s entries", name)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", errors.New("invalid checksum file SHA-256")
		}
		foundEntries[name] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksum file: %w", err)
	}
	found := foundEntries[filename]
	if found == "" {
		return "", fmt.Errorf("checksum file has no %s entry", filename)
	}
	return found, nil
}

type buildManifest struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"format_version"`
	Version       string `json:"version"`
	Source        struct {
		WorkingTreeDirty bool `json:"working_tree_dirty"`
		BinaryModified   bool `json:"binary_vcs_modified"`
		ChecksSkipped    bool `json:"checks_skipped"`
	} `json:"source"`
	Target struct {
		GOOS         string `json:"goos"`
		GOARCH       string `json:"goarch"`
		GOAMD64      string `json:"goamd64"`
		CGOEnabled   string `json:"cgo_enabled"`
		GUISubsystem bool   `json:"gui_subsystem"`
	} `json:"target"`
	WinDivert struct {
		RuntimeSource   string `json:"runtime_source"`
		ArchiveVerified bool   `json:"archive_verified"`
		DLLSHA256       string `json:"dll_sha256"`
		DriverSHA256    string `json:"driver_sha256"`
	} `json:"windivert"`
	Executable struct {
		File                    string `json:"file"`
		Size                    int64  `json:"size"`
		SHA256                  string `json:"sha256"`
		InjectedVersionVerified bool   `json:"injected_version_verified"`
	} `json:"executable"`
}

func validateBuildManifest(content []byte, release Release, wantHash, installDirectory string) error {
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return fmt.Errorf("validate build manifest JSON: %w", err)
	}
	var manifest buildManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return fmt.Errorf("decode build manifest: %w", err)
	}
	if manifest.Format != "pitchprox.build-manifest" || manifest.FormatVersion != 1 {
		return errors.New("unsupported build manifest format")
	}
	if manifest.Version != release.Version {
		return errors.New("build manifest version does not match release tag")
	}
	if manifest.Source.WorkingTreeDirty || manifest.Source.BinaryModified || manifest.Source.ChecksSkipped {
		return errors.New("build manifest describes an unverified or modified build")
	}
	if manifest.Target.GOOS != "windows" || manifest.Target.GOARCH != "amd64" || manifest.Target.GOAMD64 != "v1" || manifest.Target.CGOEnabled != "0" || !manifest.Target.GUISubsystem {
		return errors.New("build manifest target is not supported by this updater")
	}
	if manifest.Executable.File != executableName || manifest.Executable.Size != release.executable.Size || !manifest.Executable.InjectedVersionVerified {
		return errors.New("build manifest executable metadata is invalid")
	}
	if !strings.EqualFold(manifest.Executable.SHA256, wantHash) {
		return errors.New("build manifest executable SHA-256 does not match checksum file")
	}
	if manifest.WinDivert.RuntimeSource != "verified-official-archive" || !manifest.WinDivert.ArchiveVerified {
		return errors.New("build manifest does not describe a verified WinDivert runtime")
	}
	for _, runtimeFile := range []struct {
		name string
		hash string
	}{
		{name: "WinDivert.dll", hash: manifest.WinDivert.DLLSHA256},
		{name: "WinDivert64.sys", hash: manifest.WinDivert.DriverSHA256},
	} {
		if err := verifyLocalFileSHA256(filepath.Join(installDirectory, runtimeFile.name), runtimeFile.hash); err != nil {
			return fmt.Errorf("installed %s is incompatible with this release: %w", runtimeFile.name, err)
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func verifyLocalFileSHA256(path, expected string) error {
	if len(expected) != 64 {
		return errors.New("manifest contains an invalid SHA-256")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("manifest contains an invalid SHA-256")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, 64<<10)); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return errors.New("SHA-256 does not match the release manifest; install the full package manually")
	}
	return nil
}
