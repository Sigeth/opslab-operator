package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/content/memory"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/ocipkg"
)

var pinnedImage = "docker.io/library/debian:13-slim@" + digest.FromString("debian").String()

// fakeRegistry serves packages packed in memory, by reference.
type fakeRegistry struct {
	packages map[string]*ocipkg.Package
	err      error
	fetches  int
}

func (f *fakeRegistry) Fetch(_ context.Context, ref string) (*ocipkg.Package, error) {
	f.fetches++
	if f.err != nil {
		return nil, f.err
	}
	p, ok := f.packages[ref]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

// publish packs manifest with files and serves it at ref.
func (f *fakeRegistry) publish(t *testing.T, ref, manifest string, files map[string][]byte) *ocipkg.Package {
	t.Helper()
	ctx := context.Background()
	pkg, err := challenge.Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	desc, err := ocipkg.Pack(ctx, store, pkg, files)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := ocipkg.Fetch(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if f.packages == nil {
		f.packages = map[string]*ocipkg.Package{}
	}
	f.packages[ref] = fetched
	return fetched
}

var helloFiles = map[string][]byte{"setup/setup.sh": []byte("echo broken > /tmp/state\n"), "instructions/en.md": []byte("# Hello\n")}

func ociChallenge(ref string, trust v1alpha1.TrustPolicy) *v1alpha1.Challenge {
	return &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			OCI: &v1alpha1.OCIPackageRef{Ref: ref, Trust: trust},
		}},
	}
}

var unsigned = v1alpha1.TrustPolicy{AllowUnsigned: true}

func readyCondition(t *testing.T, ch *v1alpha1.Challenge) *metav1.Condition {
	t.Helper()
	cond := meta.FindStatusCondition(ch.Status.Conditions, v1alpha1.ConditionReady)
	if cond == nil {
		t.Fatalf("no Ready condition in %+v", ch.Status)
	}
	return cond
}

func TestChallengeInstallFromOCI(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	reg := &fakeRegistry{}
	published := reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	c := newClient(t, ociChallenge(ref, unsigned))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)

	got := get(t, c, key, &v1alpha1.Challenge{})
	st := got.Status
	if cond := readyCondition(t, got); cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v", cond)
	}
	if st.Digest != published.Descriptor.Digest.String() || st.FilesConfigMap != "challenge-hello-package" || !st.Runnable {
		t.Fatalf("status = %+v", st)
	}
	if st.Package.Spec.Lifetime == nil {
		t.Error("the package must be defaulted")
	}

	cm := get(t, c, types.NamespacedName{Namespace: systemNS, Name: st.FilesConfigMap}, &corev1.ConfigMap{})
	if cm.Annotations[v1alpha1.PackageDigestAnnotation] != st.Digest {
		t.Errorf("annotations = %v", cm.Annotations)
	}
	if len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Name != "hello" || cm.OwnerReferences[0].Kind != "Challenge" {
		t.Errorf("owner references = %+v", cm.OwnerReferences)
	}
	files, err := installedFiles(context.Background(), c, systemNS, got)
	if err != nil || string(files["setup/setup.sh"]) != string(helloFiles["setup/setup.sh"]) {
		t.Fatalf("installed files = %v, %v", files, err)
	}

	// The installed digest is kept: no fetch until the Challenge changes.
	doReconcile(t, r, key)
	if reg.fetches != 1 {
		t.Fatalf("fetched %d times, want 1", reg.fetches)
	}
	got.Generation = 2
	got.Spec.Disabled = true
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if reg.fetches != 2 {
		t.Fatalf("fetched %d times after a change, want 2", reg.fetches)
	}
}

func TestChallengeFromOCIRefusals(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	cases := map[string]struct {
		manifest string
		trust    v1alpha1.TrustPolicy
		want     string
		fetches  int
	}{
		"signed packages fail closed": {
			strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1),
			v1alpha1.TrustPolicy{Keys: []string{"key"}}, "signature", 0,
		},
		"unpinned images": {testManifest, unsigned, "pinned by digest", 1},
		"name mismatch": {
			strings.Replace(strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), "name: hello", "name: other", 1),
			unsigned, "named after", 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			reg := &fakeRegistry{}
			reg.publish(t, ref, tc.manifest, helloFiles)
			c := newClient(t, ociChallenge(ref, tc.trust))
			r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
			res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
			got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
			cond := readyCondition(t, got)
			if cond.Status != metav1.ConditionFalse || cond.Reason != "Invalid" || !strings.Contains(cond.Message, tc.want) {
				t.Fatalf("condition = %+v", cond)
			}
			if res.RequeueAfter != 0 || reg.fetches != tc.fetches || got.Status.FilesConfigMap != "" {
				t.Fatalf("requeue = %v, fetches = %d, status = %+v", res.RequeueAfter, reg.fetches, got.Status)
			}
		})
	}
}

func TestChallengeFromOCIRetriesRegistryFailures(t *testing.T) {
	reg := &fakeRegistry{err: errors.New("connection refused")}
	c := newClient(t, ociChallenge("registry.example/hello:0.1.0", unsigned))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
	cond := readyCondition(t, get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}))
	if cond.Reason != "FetchFailed" || res.RequeueAfter != fetchRetry {
		t.Fatalf("condition = %+v, requeue = %v", cond, res.RequeueAfter)
	}
}

func TestInstalledFilesRefuseAnotherDigest(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge-hello-package", Namespace: systemNS,
			Annotations: map[string]string{v1alpha1.PackageDigestAnnotation: "sha256:old"}},
	}
	ch := &v1alpha1.Challenge{ObjectMeta: metav1.ObjectMeta{Name: "hello"},
		Status: v1alpha1.ChallengeStatus{Digest: "sha256:new", FilesConfigMap: cm.Name}}
	if _, err := installedFiles(context.Background(), newClient(t, cm), systemNS, ch); err == nil ||
		!strings.Contains(err.Error(), "being updated") {
		t.Fatalf("error = %v", err)
	}
}
