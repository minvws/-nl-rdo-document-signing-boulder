//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func setup() (*exec.Cmd, *bytes.Buffer, akamaipb.AkamaiPurgerClient, error) {
	purgerCmd := exec.Command("./bin/akamai-purger", "--config", "test/integration/testdata/akamai-purger-queue-drain-config.json")
	var outputBuffer bytes.Buffer
	purgerCmd.Stdout = &outputBuffer
	purgerCmd.Stderr = &outputBuffer
	purgerCmd.Start()

	// If we error, we need to kill the process we started or the test command
	// will never exit.
	sigterm := func() {
		purgerCmd.Process.Signal(syscall.SIGTERM)
	}

	s := func(input string) *string {
		return &input
	}
	tlsConfig, err := (&cmd.TLSConfig{
		CACertFile: s("test/grpc-creds/minica.pem"),
		CertFile:   s("test/grpc-creds/ra.boulder/cert.pem"),
		KeyFile:    s("test/grpc-creds/ra.boulder/key.pem"),
	}).Load()
	if err != nil {
		sigterm()
		return nil, nil, nil, err
	}
	creds := bcreds.NewClientCredentials(tlsConfig.RootCAs, tlsConfig.Certificates, "akamai-purger.boulder")
	conn, err := grpc.Dial(
		"dns:///akamai-purger.boulder:9199",
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		sigterm()
		return nil, nil, nil, err
	}
	for i := 0; ; i++ {
		if conn.GetState() == connectivity.Ready {
			break
		}
		if i > 40 {
			sigterm()
			return nil, nil, nil, fmt.Errorf("timed out waiting for akamai-purger to come up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	purgerClient := akamaipb.NewAkamaiPurgerClient(conn)
	return purgerCmd, &outputBuffer, purgerClient, nil
}

func TestAkamaiPurgerDrainQueueFails(t *testing.T) {
	purgerCmd, outputBuffer, purgerClient, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	_, err = purgerClient.Purge(context.Background(), &akamaipb.PurgeRequest{
		Urls: []string{"http://example.com/"},
	})
	if err != nil {
		// Don't use t.Fatal here because we need to get as far as the SIGTERM or
		// we'll hang on exit.
		t.Error(err)
	}

	purgerCmd.Process.Signal(syscall.SIGTERM)
	err = purgerCmd.Wait()
	if err == nil {
		t.Error("expected error shutting down akamai-purger that could not reach backend")
	}
	expectedOutput := "failed to purge OCSP responses for 1 certificates before exit: all attempts to submit purge request failed"
	if !strings.Contains(outputBuffer.String(), expectedOutput) {
		t.Errorf("akamai-purger stdout did not contain expected %q. Output was:\n%s", expectedOutput, outputBuffer.String())
	}
}

func TestAkamaiPurgerDrainQueueSucceeds(t *testing.T) {
	purgerCmd, outputBuffer, purgerClient, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_, err := purgerClient.Purge(context.Background(), &akamaipb.PurgeRequest{
			Urls: []string{"http://example.com/"},
		})
		if err != nil {
			t.Error(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	purgerCmd.Process.Signal(syscall.SIGTERM)

	akamaiTestSrvCmd := exec.Command("./bin/akamai-test-srv", "--listen", "localhost:6889",
		"--secret", "its-a-secret")
	akamaiTestSrvCmd.Stdout = os.Stdout
	akamaiTestSrvCmd.Stderr = os.Stderr
	akamaiTestSrvCmd.Start()

	err = purgerCmd.Wait()
	if err != nil {
		t.Errorf("unexpected error shutting down akamai-purger: %s. Output was:\n%s", err, outputBuffer.String())
	}
	expectedOutput := "Shutting down; finished purging OCSP responses for 10 certificates."
	if !strings.Contains(outputBuffer.String(), expectedOutput) {
		t.Errorf("akamai-purger stdout did not contain expected %q. Output was:\n%s", expectedOutput, outputBuffer.String())
	}
	akamaiTestSrvCmd.Process.Signal(syscall.SIGTERM)
	_ = akamaiTestSrvCmd.Wait()
}
