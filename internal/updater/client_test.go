package updater

import (
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubClientListReleasesSortsFiltersAndKeepsComparisonWindow(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	releases := []githubRelease{
		testGitHubRelease("v0.44", 44, baseTime.Add(3*time.Hour), false, false),
		testGitHubRelease("v0.47", 47, baseTime.Add(5*time.Hour), false, false),
		testGitHubRelease("v9.0", 900, baseTime.Add(100*time.Hour), true, false),
		testGitHubRelease("v0.43", 43, baseTime.Add(2*time.Hour), false, false),
		testGitHubRelease("v0.49", 49, baseTime.Add(7*time.Hour), false, false),
		testGitHubRelease("v0.45", 45, baseTime.Add(4*time.Hour), false, false),
		testGitHubRelease("v0.46", 46, baseTime.Add(5*time.Hour), false, false),
		testGitHubRelease("v0.48", 48, baseTime.Add(6*time.Hour), false, false),
		testGitHubRelease("v0.42", 42, time.Time{}, false, false),
	}
	body, err := json.Marshal(releases)
	if err != nil {
		t.Fatal(err)
	}

	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q, want application/vnd.github+json", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != githubAPIVersion {
			t.Errorf("X-GitHub-Api-Version = %q, want %q", got, githubAPIVersion)
		}
		if got := r.Header.Get("User-Agent"); got == "" {
			t.Error("User-Agent is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))

	got, err := client.ListReleases(context.Background())
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("len(ListReleases) = %d, want 7", len(got))
	}
	wantVersions := []string{"v0.49", "v0.48", "v0.47", "v0.46", "v0.45", "v0.44", "v0.43"}
	for i, want := range wantVersions {
		if got[i].Version != want {
			t.Errorf("release[%d].Version = %q, want %q", i, got[i].Version, want)
		}
	}
	if got[2].PublishedAt != got[3].PublishedAt || got[2].id <= got[3].id {
		t.Fatalf("equal timestamps were not ordered by descending id: %#v then %#v", got[2], got[3])
	}
}

func TestGitHubClientListReleasesMarksPrereleaseMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		version    string
		prerelease bool
	}{
		{name: "prerelease tag marked stable", version: "v0.43-rc.4", prerelease: false},
		{name: "stable tag marked prerelease", version: "v0.43", prerelease: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := []githubRelease{
				testGitHubRelease(test.version, 1, time.Now().UTC(), false, test.prerelease),
			}
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			client := newTestGitHubClient(t, staticResponseHandler(body))

			releases, err := client.ListReleases(context.Background())
			if err != nil {
				t.Fatalf("ListReleases: %v", err)
			}
			if len(releases) != 1 {
				t.Fatalf("len(ListReleases) = %d, want 1", len(releases))
			}
			if releases[0].Installable {
				t.Fatal("release with mismatched prerelease metadata is installable")
			}
			if !strings.Contains(releases[0].Reason, "prerelease") {
				t.Fatalf("Reason = %q, want prerelease mismatch", releases[0].Reason)
			}
		})
	}
}

func TestGitHubClientListReleasesShowsButRejectsNonCanonicalTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version    string
		prerelease bool
	}{
		{version: "V0.43"},
		{version: "v01.2"},
		{version: "v1.02"},
		{version: "v1.2.03"},
		{version: "v1.2+build.1"},
		{version: "v1.2-rc.01", prerelease: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			response := []githubRelease{
				testGitHubRelease(test.version, 1, time.Now().UTC(), false, test.prerelease),
			}
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			client := newTestGitHubClient(t, staticResponseHandler(body))

			releases, err := client.ListReleases(context.Background())
			if err != nil {
				t.Fatalf("ListReleases: %v", err)
			}
			if len(releases) != 1 {
				t.Fatalf("len(ListReleases) = %d, want the non-canonical release to remain visible", len(releases))
			}
			if releases[0].Version != test.version {
				t.Fatalf("Version = %q, want %q", releases[0].Version, test.version)
			}
			if releases[0].Installable {
				t.Fatalf("non-canonical release %q is installable", test.version)
			}
			if !strings.Contains(releases[0].Reason, "формат версии") {
				t.Fatalf("Reason = %q, want unsupported version format", releases[0].Reason)
			}
		})
	}
}

func TestGitHubClientListReleasesRejectsDuplicateAssets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		duplicate  string
		wantReason string
	}{
		{name: "executable", duplicate: executableName, wantReason: executableName},
		{name: "checksums", duplicate: checksumsName, wantReason: checksumsName},
		{name: "manifest", duplicate: manifestName, wantReason: "манифеста"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			item := testGitHubRelease("v0.43", 1, time.Now().UTC(), false, false)
			for _, candidate := range item.Assets {
				if candidate.Name == test.duplicate {
					candidate.ID += 1000
					item.Assets = append(item.Assets, candidate)
					break
				}
			}
			body, err := json.Marshal([]githubRelease{item})
			if err != nil {
				t.Fatal(err)
			}
			client := newTestGitHubClient(t, staticResponseHandler(body))

			releases, err := client.ListReleases(context.Background())
			if err != nil {
				t.Fatalf("ListReleases: %v", err)
			}
			if len(releases) != 1 {
				t.Fatalf("len(ListReleases) = %d, want 1", len(releases))
			}
			if releases[0].Installable {
				t.Fatalf("release with duplicate %s is installable", test.duplicate)
			}
			if !strings.Contains(releases[0].Reason, test.wantReason) {
				t.Fatalf("Reason = %q, want substring %q", releases[0].Reason, test.wantReason)
			}
		})
	}
}

func TestGitHubClientRecoversIncompleteNestedAssets(t *testing.T) {
	for _, nestedCount := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("nested-%d", nestedCount), func(t *testing.T) {
			t.Parallel()
			item := testGitHubRelease("v0.44", 394494379, time.Now().UTC(), false, false)
			complete := append([]githubAsset(nil), item.Assets...)
			item.Assets = item.Assets[:nestedCount]
			// Ignore server-provided URLs; IDs form canonical repository URLs.
			complete[0].URL = "https://untrusted.invalid/payload"
			complete[0].ID++
			complete[0].Size = 2048
			var requests atomic.Int32
			client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch r.URL.Path {
				case "/releases":
					_ = json.NewEncoder(w).Encode([]githubRelease{item})
				case "/repos/agentpitch/prox/releases/394494379/assets":
					if r.URL.Query().Get("per_page") != "33" || r.URL.Query().Get("page") != "1" {
						t.Errorf("unbounded query: %s", r.URL.RawQuery)
					}
					if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != githubAPIVersion {
						t.Error("fallback lost GitHub API headers")
					}
					_ = json.NewEncoder(w).Encode(complete)
				default:
					t.Errorf("unexpected endpoint %s", r.URL)
					w.WriteHeader(404)
				}
			}))
			got, err := client.ListReleases(context.Background())
			if err != nil || len(got) != 1 || !got[0].Installable || got[0].Verification != "manifest" {
				t.Fatalf("ListReleases=%+v, %v", got, err)
			}
			if requests.Load() != 2 || got[0].executable.ID != complete[0].ID || got[0].Size != complete[0].Size || got[0].executable.APIURL != client.assetURL(complete[0].ID) {
				t.Fatalf("lookup did not replace asset snapshot safely: %+v, requests %d", got[0], requests.Load())
			}
		})
	}
}

func TestGitHubClientFallbackStillRequiresStrictAssets(t *testing.T) {
	for _, mode := range []string{"empty", "missing_manifest", "duplicate_executable", "invalid_digest", "too_many", "server_error", "invalid_json", "oversized_response"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			item := testGitHubRelease("v0.44", 44, time.Now().UTC(), false, false)
			assets := append([]githubAsset(nil), item.Assets...)
			item.Assets = nil
			switch mode {
			case "empty":
				assets = nil
			case "missing_manifest":
				assets = assets[:2]
			case "duplicate_executable":
				assets = append(assets, assets[0])
			case "invalid_digest":
				assets[0].Digest = ""
			case "too_many":
				for len(assets) <= maxReleaseAssets {
					assets = append(assets, testGitHubAsset(int64(1000+len(assets)), fmt.Sprintf("extra-%d", len(assets)), 100))
				}
			}
			var requests atomic.Int32
			client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/releases" {
					_ = json.NewEncoder(w).Encode([]githubRelease{item})
					return
				}
				if mode == "server_error" {
					w.WriteHeader(503)
					return
				}
				if mode == "invalid_json" {
					_, _ = w.Write([]byte(`{"not":"a list"}`))
					return
				}
				if mode == "oversized_response" {
					_, _ = w.Write([]byte(strings.Repeat(" ", int(maxReleaseJSON)+1)))
					return
				}
				// No pagination following: 33 entries already prove overflow.
				w.Header().Set("Link", `<https://untrusted.invalid/next>; rel="next"`)
				_ = json.NewEncoder(w).Encode(assets)
			}))
			got, err := client.ListReleases(context.Background())
			if err != nil || len(got) != 1 || got[0].Installable || got[0].Reason == "" {
				t.Fatalf("unsafe fallback result=%+v, %v", got, err)
			}
			if requests.Load() != 2 {
				t.Fatalf("requests=%d; want one bounded fallback", requests.Load())
			}
			if (mode == "server_error" || mode == "invalid_json" || mode == "oversized_response") && !strings.Contains(got[0].Reason, "полный список файлов") {
				t.Fatalf("lookup failure hidden: %s", got[0].Reason)
			}
		})
	}
}

func TestGitHubClientAssetFallbackPreservesLegacyArchiveRequirement(t *testing.T) {
	t.Parallel()
	item := testGitHubRelease("v0.41", 41, time.Now().UTC(), false, false)
	item.Assets = item.Assets[:2]
	complete := append(append([]githubAsset(nil), item.Assets...), testGitHubAsset(413, archiveName, 4096))
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases" {
			_ = json.NewEncoder(w).Encode([]githubRelease{item})
			return
		}
		_ = json.NewEncoder(w).Encode(complete)
	}))
	got, err := client.ListReleases(context.Background())
	if err != nil || len(got) != 1 || !got[0].Installable || got[0].Verification != "legacy" || got[0].archive.ID != 413 {
		t.Fatalf("legacy fallback=%+v, %v", got, err)
	}
}

func TestGitHubClientDoesNotRepairKnownInvalidReleaseMetadata(t *testing.T) {
	for _, mode := range []string{"duplicate", "invalid_digest", "invalid_size", "pending_upload", "noncanonical", "prerelease_mismatch", "missing_id", "too_many"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			item := testGitHubRelease("v0.44", 44, time.Now().UTC(), false, false)
			item.Assets = item.Assets[:2] // A missing manifest alone would allow lookup.
			switch mode {
			case "duplicate":
				item.Assets = append(item.Assets, item.Assets[0])
			case "invalid_digest":
				item.Assets[0].Digest = ""
			case "invalid_size":
				item.Assets[0].Size = 0
			case "pending_upload":
				item.Assets[0].State = "new"
			case "noncanonical":
				item.TagName = "v00.44"
			case "prerelease_mismatch":
				item.TagName = "v0.44-rc.1"
			case "missing_id":
				item.ID = 0
			case "too_many":
				for len(item.Assets) <= maxReleaseAssets {
					item.Assets = append(item.Assets, testGitHubAsset(int64(1000+len(item.Assets)), fmt.Sprintf("extra-%d", len(item.Assets)), 100))
				}
			}
			var requests atomic.Int32
			client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/releases" {
					t.Errorf("known invalid metadata triggered fallback %s", r.URL)
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode([]githubRelease{item})
			}))
			got, err := client.ListReleases(context.Background())
			if err != nil || len(got) != 1 || got[0].Installable || requests.Load() != 1 {
				t.Fatalf("invalid metadata bypassed: %+v, %v; requests %d", got, err, requests.Load())
			}
		})
	}
}

func TestGitHubClientBoundsFallbackToMostRecentVisibleReleases(t *testing.T) {
	t.Parallel()
	base := time.Now().UTC()
	var response []githubRelease
	for id := 1; id <= 30; id++ {
		item := testGitHubRelease(fmt.Sprintf("v0.%d", id+50), int64(id), base.Add(time.Duration(id)*time.Hour), false, false)
		item.Assets = nil
		response = append(response, item)
	}
	response = append(response, testGitHubRelease("v999.0", 999, base.Add(999*time.Hour), true, false))
	response = append(response, testGitHubRelease("v999.1", 1000, time.Time{}, false, false))
	var requests atomic.Int32
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/releases" {
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		var id int
		if _, err := fmt.Sscanf(r.URL.Path, "/repos/agentpitch/prox/releases/%d/assets", &id); err != nil || id < 26 || id > 30 {
			t.Errorf("lookup outside newest five: %s", r.URL)
		}
		complete := testGitHubRelease("v0.80", int64(id), base, false, false)
		_ = json.NewEncoder(w).Encode(complete.Assets)
	}))
	got, err := client.ListReleases(context.Background())
	if err != nil || len(got) != maxReleaseResults {
		t.Fatalf("comparison window len=%d, %v", len(got), err)
	}
	if requests.Load() != 1+maxVisibleReleases {
		t.Fatalf("requests=%d, want %d", requests.Load(), 1+maxVisibleReleases)
	}
	for i, item := range got {
		if item.id != int64(30-i) || item.Installable != (i < maxVisibleReleases) {
			t.Fatalf("result[%d]=%+v", i, item)
		}
	}
}

func TestGitHubClientCompleteNestedAssetsDoNotAddRequests(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	item := testGitHubRelease("v0.44", 44, time.Now().UTC(), false, false)
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/releases" {
			t.Errorf("complete metadata triggered fallback %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode([]githubRelease{item})
	}))
	got, err := client.ListReleases(context.Background())
	if err != nil || len(got) != 1 || !got[0].Installable || requests.Load() != 1 {
		t.Fatalf("complete result=%+v, %v; requests%d", got, err, requests.Load())
	}
}

func TestGitHubClientAssetLookupHonorsCancellation(t *testing.T) {
	t.Parallel()
	item := testGitHubRelease("v0.44", 44, time.Now().UTC(), false, false)
	item.Assets = nil
	started := make(chan struct{})
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases" {
			_ = json.NewEncoder(w).Encode([]githubRelease{item})
			return
		}
		close(started)
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.ListReleases(ctx); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not cancel")
	}
}

func TestChecksumFor(t *testing.T) {
	t.Parallel()

	exeHash := strings.Repeat("A", 64)
	zipHash := strings.Repeat("b", 64)
	manifestHash := strings.Repeat("c", 64)
	valid := []byte(fmt.Sprintf(
		"%s *%s\r\n%s *pitchProx-windows-amd64.zip\r\n%s *%s\r\n",
		exeHash, executableName, zipHash, manifestHash, manifestName,
	))
	got, err := checksumFor(valid, executableName)
	if err != nil {
		t.Fatalf("checksumFor(valid): %v", err)
	}
	if got != strings.ToLower(exeHash) {
		t.Fatalf("checksumFor(valid) = %q, want %q", got, strings.ToLower(exeHash))
	}

	tests := []struct {
		name    string
		content string
		file    string
		want    string
	}{
		{
			name:    "duplicate",
			content: fmt.Sprintf("%s *%s\n%s *%s\n", exeHash, executableName, exeHash, executableName),
			file:    executableName,
			want:    "duplicate",
		},
		{
			name:    "unexpected path",
			content: fmt.Sprintf("%s *../%s\n", exeHash, executableName),
			file:    executableName,
			want:    "unexpected file",
		},
		{
			name:    "missing requested file",
			content: fmt.Sprintf("%s *pitchProx-windows-amd64.zip\n", zipHash),
			file:    executableName,
			want:    "has no",
		},
		{
			name:    "invalid hash",
			content: fmt.Sprintf("%s *%s\n", strings.Repeat("g", 64), executableName),
			file:    executableName,
			want:    "SHA-256",
		},
		{
			name:    "UTF-8 BOM",
			content: "\ufeff" + fmt.Sprintf("%s *%s\n", exeHash, executableName),
			file:    executableName,
			want:    "format",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := checksumFor([]byte(test.content), test.file)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("checksumFor error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateBuildManifest(t *testing.T) {
	tests := []struct {
		name           string
		mutateManifest func(*buildManifest)
		mutateFiles    func(*testing.T, string)
		wantError      string
	}{
		{name: "valid"},
		{
			name: "wrong release version",
			mutateManifest: func(manifest *buildManifest) {
				manifest.Version = "v0.44"
			},
			wantError: "version",
		},
		{
			name: "dirty build",
			mutateManifest: func(manifest *buildManifest) {
				manifest.Source.WorkingTreeDirty = true
			},
			wantError: "unverified or modified",
		},
		{
			name: "wrong target",
			mutateManifest: func(manifest *buildManifest) {
				manifest.Target.GOARCH = "arm64"
			},
			wantError: "target",
		},
		{
			name: "wrong executable hash",
			mutateManifest: func(manifest *buildManifest) {
				manifest.Executable.SHA256 = strings.Repeat("0", 64)
			},
			wantError: "checksum file",
		},
		{
			name: "unverified WinDivert archive",
			mutateManifest: func(manifest *buildManifest) {
				manifest.WinDivert.ArchiveVerified = false
			},
			wantError: "verified WinDivert",
		},
		{
			name: "installed WinDivert tampered",
			mutateFiles: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, "WinDivert.dll"), []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "incompatible",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := updaterTestTempDir(t)
			dllHash, driverHash := writeTestWinDivertRuntime(t, directory)
			executable := minimalPE(pe.IMAGE_FILE_MACHINE_AMD64)
			executableHash := sha256Hex(executable)
			release := Release{
				Version: "v0.43",
				executable: asset{
					Name: executableName,
					Size: int64(len(executable)),
				},
			}
			manifest := testBuildManifest(release, executableHash, dllHash, driverHash)
			if test.mutateManifest != nil {
				test.mutateManifest(&manifest)
			}
			if test.mutateFiles != nil {
				test.mutateFiles(t, directory)
			}
			content, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}

			err = validateBuildManifest(content, release, executableHash, directory)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateBuildManifest: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateBuildManifest error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestGitHubClientStageVerifiedExecutable(t *testing.T) {
	directory := updaterTestTempDir(t)
	dllHash, driverHash := writeTestWinDivertRuntime(t, directory)
	executable := minimalPE(pe.IMAGE_FILE_MACHINE_AMD64)
	executableHash := sha256Hex(executable)

	responses := map[string][]byte{}
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, ok := responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	}))
	release := Release{
		Version:     "v0.43",
		Installable: true,
		executable:  asset{ID: 1, Name: executableName, Size: int64(len(executable)), State: "uploaded"},
		checksums:   asset{ID: 2, Name: checksumsName, State: "uploaded"},
		manifest:    asset{ID: 3, Name: manifestName, State: "uploaded"},
	}
	release.executable.APIURL = client.assetURL(release.executable.ID)
	release.checksums.APIURL = client.assetURL(release.checksums.ID)
	release.manifest.APIURL = client.assetURL(release.manifest.ID)

	manifest := testBuildManifest(release, executableHash, dllHash, driverHash)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256Hex(manifestBytes)
	checksumBytes := []byte(fmt.Sprintf(
		"%s *%s\n%s *pitchProx-windows-amd64.zip\n%s *%s\n",
		executableHash, executableName, strings.Repeat("0", 64), manifestHash, manifestName,
	))
	release.executable.Digest = "sha256:" + executableHash
	release.checksums.Size = int64(len(checksumBytes))
	release.checksums.Digest = "sha256:" + sha256Hex(checksumBytes)
	release.manifest.Size = int64(len(manifestBytes))
	release.manifest.Digest = "sha256:" + manifestHash
	responses[clientPath(release.executable.APIURL)] = executable
	responses[clientPath(release.checksums.APIURL)] = checksumBytes
	responses[clientPath(release.manifest.APIURL)] = manifestBytes

	destination := filepath.Join(directory, "pitchProx-update.exe")
	var lastDownloaded, lastTotal atomic.Int64
	err = client.Stage(context.Background(), release, destination, func(downloaded, total int64) {
		lastDownloaded.Store(downloaded)
		lastTotal.Store(total)
	})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(got) != executableHash {
		t.Fatal("staged executable differs from downloaded executable")
	}
	if lastDownloaded.Load() != int64(len(executable)) || lastTotal.Load() != int64(len(executable)) {
		t.Fatalf("last progress = (%d, %d), want (%d, %d)", lastDownloaded.Load(), lastTotal.Load(), len(executable), len(executable))
	}
}

func TestDownloadVerifiedBytesRejectsTamperSizeAndOversize(t *testing.T) {
	t.Parallel()

	t.Run("tampered hash", func(t *testing.T) {
		t.Parallel()
		body := []byte("tampered")
		client := newTestGitHubClient(t, staticResponseHandler(body))
		item := asset{
			Name:   checksumsName,
			APIURL: client.releasesURL.String(),
			Size:   int64(len(body)),
			Digest: "sha256:" + sha256Hex([]byte("expected")),
		}
		_, err := client.downloadVerifiedBytes(context.Background(), item, maxChecksumBytes, "checksum file")
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("downloadVerifiedBytes error = %v, want hash mismatch", err)
		}
	})

	t.Run("metadata size mismatch", func(t *testing.T) {
		t.Parallel()
		body := []byte("short")
		client := newTestGitHubClient(t, staticResponseHandler(body))
		item := asset{
			Name:   checksumsName,
			APIURL: client.releasesURL.String(),
			Size:   int64(len(body) + 1),
			Digest: "sha256:" + sha256Hex(body),
		}
		_, err := client.downloadVerifiedBytes(context.Background(), item, maxChecksumBytes, "checksum file")
		if err == nil || !strings.Contains(err.Error(), "size differs") {
			t.Fatalf("downloadVerifiedBytes error = %v, want size mismatch", err)
		}
	})

	t.Run("body exceeds limit", func(t *testing.T) {
		t.Parallel()
		body := make([]byte, maxChecksumBytes+1)
		client := newTestGitHubClient(t, staticResponseHandler(body))
		_, err := client.getBytes(context.Background(), client.releasesURL.String(), "application/octet-stream", maxChecksumBytes, int64(len(body)), "checksum file")
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("getBytes error = %v, want oversize error", err)
		}
	})
}

func TestDownloadExecutableVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		body          []byte
		wantHash      string
		sizeDelta     int64
		wantError     string
		wantInstalled bool
	}{
		{
			name:          "valid AMD64 PE",
			body:          minimalPE(pe.IMAGE_FILE_MACHINE_AMD64),
			wantInstalled: true,
		},
		{
			name:      "tampered hash",
			body:      minimalPE(pe.IMAGE_FILE_MACHINE_AMD64),
			wantHash:  strings.Repeat("0", 64),
			wantError: "SHA-256 verification failed",
		},
		{
			name:      "metadata size mismatch",
			body:      minimalPE(pe.IMAGE_FILE_MACHINE_AMD64),
			sizeDelta: 1,
			wantError: "size differs",
		},
		{
			name:      "not a PE file",
			body:      []byte("not a portable executable"),
			wantError: "not a valid PE",
		},
		{
			name:      "wrong PE machine",
			body:      minimalPE(pe.IMAGE_FILE_MACHINE_I386),
			wantError: "expected AMD64",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := newTestGitHubClient(t, staticResponseHandler(test.body))
			wantHash := test.wantHash
			if wantHash == "" {
				wantHash = sha256Hex(test.body)
			}
			item := asset{
				Name:   executableName,
				APIURL: client.releasesURL.String(),
				Size:   int64(len(test.body)) + test.sizeDelta,
			}
			destination := filepath.Join(updaterTestTempDir(t), executableName)
			err := client.downloadExecutable(context.Background(), item, destination, wantHash, nil)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("downloadExecutable: %v", err)
				}
				if _, err := os.Stat(destination); err != nil {
					t.Fatalf("staged executable missing: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("downloadExecutable error = %v, want substring %q", err, test.wantError)
			}
			if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
				t.Fatalf("rejected destination remains on disk: %v", statErr)
			}
			if _, statErr := os.Stat(destination + ".part"); !os.IsNotExist(statErr) {
				t.Fatalf("partial file remains on disk: %v", statErr)
			}
		})
	}
}

func TestDownloadExecutableRejectsOversizeBeforeRequest(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	item := asset{
		Name:   executableName,
		APIURL: client.releasesURL.String(),
		Size:   maxExecutableBytes + 1,
	}
	err := client.downloadExecutable(context.Background(), item, filepath.Join(updaterTestTempDir(t), executableName), strings.Repeat("0", 64), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid executable size") {
		t.Fatalf("downloadExecutable error = %v, want invalid size", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server received %d requests for an already-oversized asset", got)
	}
}

func TestGitHubClientRejectsRedirectToUntrustedHost(t *testing.T) {
	t.Parallel()

	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/update.exe", http.StatusFound)
	}))
	_, err := client.getBytes(context.Background(), client.releasesURL.String(), "application/octet-stream", 1024, 0, "redirect test")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("getBytes redirect error = %v, want untrusted-host rejection", err)
	}
}

func newTestGitHubClient(t *testing.T, handler http.Handler) *GitHubClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewGitHubClient(ClientOptions{
		ReleasesURL: server.URL + "/releases",
		AllowHTTP:   true,
	})
	if err != nil {
		t.Fatalf("NewGitHubClient: %v", err)
	}
	return client
}

func staticResponseHandler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
}

func testGitHubRelease(version string, id int64, published time.Time, draft, prerelease bool) githubRelease {
	return githubRelease{
		ID:          id,
		TagName:     version,
		Name:        version,
		HTMLURL:     "https://github.com/agentpitch/prox/releases/tag/" + version,
		Draft:       draft,
		Prerelease:  prerelease,
		PublishedAt: published,
		Assets: []githubAsset{
			testGitHubAsset(id*10+1, executableName, 1024),
			testGitHubAsset(id*10+2, checksumsName, 270),
			testGitHubAsset(id*10+3, manifestName, 4096),
		},
	}
}

func testGitHubAsset(id int64, name string, size int64) githubAsset {
	return githubAsset{
		ID:          id,
		Name:        name,
		State:       "uploaded",
		Size:        size,
		Digest:      "sha256:" + strings.Repeat("0", 64),
		ContentType: "application/octet-stream",
	}
}

func testBuildManifest(release Release, executableHash, dllHash, driverHash string) buildManifest {
	var manifest buildManifest
	manifest.Format = "pitchprox.build-manifest"
	manifest.FormatVersion = 1
	manifest.Version = release.Version
	manifest.Target.GOOS = "windows"
	manifest.Target.GOARCH = "amd64"
	manifest.Target.GOAMD64 = "v1"
	manifest.Target.CGOEnabled = "0"
	manifest.Target.GUISubsystem = true
	manifest.WinDivert.RuntimeSource = "verified-official-archive"
	manifest.WinDivert.ArchiveVerified = true
	manifest.WinDivert.DLLSHA256 = dllHash
	manifest.WinDivert.DriverSHA256 = driverHash
	manifest.Executable.File = executableName
	manifest.Executable.Size = release.executable.Size
	manifest.Executable.SHA256 = executableHash
	manifest.Executable.InjectedVersionVerified = true
	return manifest
}

func writeTestWinDivertRuntime(t *testing.T, directory string) (string, string) {
	t.Helper()
	dll := []byte("test WinDivert.dll")
	driver := []byte("test WinDivert64.sys")
	if err := os.WriteFile(filepath.Join(directory, "WinDivert.dll"), dll, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "WinDivert64.sys"), driver, 0o600); err != nil {
		t.Fatal(err)
	}
	return sha256Hex(dll), sha256Hex(driver)
}

func minimalPE(machine uint16) []byte {
	content := make([]byte, 0x80+4+20)
	content[0] = 'M'
	content[1] = 'Z'
	binary.LittleEndian.PutUint32(content[0x3c:], 0x80)
	copy(content[0x80:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(content[0x84:], machine)
	binary.LittleEndian.PutUint16(content[0x96:], 0x0002)
	return content
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func clientPath(rawURL string) string {
	parsed, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		panic(err)
	}
	return parsed.URL.Path
}
