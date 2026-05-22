package session

import (
	"testing"
	"time"
)

func baseObs(serial string, issuedAt time.Time, lifetime time.Duration, trustDomain string) CertObservation {
	return CertObservation{
		Serial:            serial,
		Expiry:            issuedAt.Add(lifetime),
		IssuerFingerprint: "fp-prod-ca",
		TrustDomain:       trustDomain,
		ObservedAt:        issuedAt,
	}
}

func TestRotationTrackerFirstObservationIsNotARotation(t *testing.T) {
	tr := NewRotationTracker()
	obs := baseObs("serial-001", time.Now(), 24*time.Hour, "prod.example.com")
	class := tr.Track("spiffe://prod.example.com/ns/app/sa/worker", obs)
	if class != RotationFirstSeen {
		t.Errorf("class = %v, want RotationFirstSeen", class)
	}
}

func TestRotationTrackerSameCertIsNotARotation(t *testing.T) {
	tr := NewRotationTracker()
	now := time.Now()
	obs := baseObs("serial-001", now, 24*time.Hour, "prod.example.com")
	tr.Track("spiffe://prod.example.com/ns/app/sa/worker", obs)

	// Same serial seen again (e.g. another connection from same cert)
	class := tr.Track("spiffe://prod.example.com/ns/app/sa/worker", obs)
	if class != RotationFirstSeen {
		t.Errorf("same cert re-observed: class = %v, want RotationFirstSeen", class)
	}
}

func TestRotationTrackerNormalScheduledRotation(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	// First cert: issued now, expires in 24h
	tr.Track(spiffeID, baseObs("serial-001", now, 24*time.Hour, "prod.example.com"))

	// New cert arrives just after the old one expired
	newObs := baseObs("serial-002", now.Add(25*time.Hour), 24*time.Hour, "prod.example.com")
	class := tr.Track(spiffeID, newObs)
	if class != RotationNormal {
		t.Errorf("class = %v, want RotationNormal", class)
	}
}

func TestRotationTrackerEarlyRotation(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	// Cert with 24h lifetime
	tr.Track(spiffeID, baseObs("serial-001", now, 24*time.Hour, "prod.example.com"))

	// New cert arrives only 2h later — well before expected expiry
	newObs := baseObs("serial-002", now.Add(2*time.Hour), 24*time.Hour, "prod.example.com")
	class := tr.Track(spiffeID, newObs)
	if class != RotationEarly {
		t.Errorf("class = %v, want RotationEarly", class)
	}
}

func TestRotationTrackerIssuerChange(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	tr.Track(spiffeID, baseObs("serial-001", now, 24*time.Hour, "prod.example.com"))

	newObs := CertObservation{
		Serial:            "serial-002",
		Expiry:            now.Add(26 * time.Hour),
		IssuerFingerprint: "fp-different-ca", // different issuer
		TrustDomain:       "prod.example.com",
		ObservedAt:        now.Add(25 * time.Hour),
	}
	class := tr.Track(spiffeID, newObs)
	if class != RotationIssuerChange {
		t.Errorf("class = %v, want RotationIssuerChange", class)
	}
}

func TestRotationTrackerDomainChange(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	tr.Track(spiffeID, baseObs("serial-001", now, 24*time.Hour, "prod.example.com"))

	// Same path key but trust domain changed in the cert content
	newObs := CertObservation{
		Serial:            "serial-002",
		Expiry:            now.Add(26 * time.Hour),
		IssuerFingerprint: "fp-prod-ca",
		TrustDomain:       "evil.corp", // trust domain change
		ObservedAt:        now.Add(25 * time.Hour),
	}
	class := tr.Track(spiffeID, newObs)
	if class != RotationDomainChange {
		t.Errorf("class = %v, want RotationDomainChange", class)
	}
}

func TestRotationTrackerHistoryCappedAtK(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	// Insert certHistoryMax+5 observations
	for i := range certHistoryMax + 5 {
		obs := baseObs(
			"serial-"+string(rune('A'+i)),
			now.Add(time.Duration(i)*25*time.Hour),
			24*time.Hour,
			"prod.example.com",
		)
		tr.Track(spiffeID, obs)
	}

	hist := tr.History(spiffeID)
	if len(hist) > certHistoryMax {
		t.Errorf("history len = %d, want <= %d", len(hist), certHistoryMax)
	}
}

func TestRotationTrackerLearnedIntervalNormalAfterBaseline(t *testing.T) {
	tr := NewRotationTracker()
	spiffeID := "spiffe://prod.example.com/ns/app/sa/worker"
	now := time.Now()

	// Build baseline: rotationLearnMin observations at 24h intervals
	for i := range rotationLearnMin {
		obs := baseObs(
			"serial-"+string(rune('A'+i)),
			now.Add(time.Duration(i)*24*time.Hour),
			24*time.Hour,
			"prod.example.com",
		)
		tr.Track(spiffeID, obs)
	}

	// Next rotation at the expected interval — should be Normal
	nextObs := baseObs(
		"serial-Z",
		now.Add(time.Duration(rotationLearnMin)*24*time.Hour),
		24*time.Hour,
		"prod.example.com",
	)
	class := tr.Track(spiffeID, nextObs)
	if class != RotationNormal {
		t.Errorf("class = %v, want RotationNormal after learned baseline", class)
	}
}
