package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"nadi-agent/internal/app"
	"nadi-agent/internal/config"
	"nadi-agent/internal/handoffbroker"
	"nadi-agent/internal/logging"
	"nadi-agent/internal/version"
)

func main() {
	if isProvisionHelperInvocation(os.Args[0]) {
		executablePath, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "unable to resolve provisioning helper executable")
			os.Exit(126)
		}

		os.Exit(runProvisionHelper(os.Args[1:], executablePath, os.Stdin, os.Stdout, os.Stderr))
	}

	showVersion := flag.Bool("version", false, "Print NADI Agent version")
	enroll := flag.Bool("enroll", false, "Enroll this Agent with NADI Central")
	manifestPath := flag.String("manifest", "", "Path to the Enrollment application manifest JSON")
	enrollmentTokenStdin := flag.Bool("enrollment-token-stdin", false, "Read the one-time Enrollment token from stdin")
	enrollmentSummaryStdout := flag.Bool("enrollment-summary-stdout", false, "Write non-secret enrollment identity metadata to stdout after enrollment")
	runHandoffBroker := flag.Bool("handoff-broker", false, "Run the root-owned local Bridge credential handoff broker")
	brokerConfigPath := flag.String("broker-config", "/etc/nadi/bridge-mappings.json", "Root-owned Bridge application mapping file")
	brokerSocketPath := flag.String("broker-socket", "/run/nadi/credential-handoff.sock", "Fixed local handoff Unix socket")
	verifyExistingIdentity := flag.Bool("verify-existing-identity-summary-stdout", false, "Verify persisted Agent identity and write a non-secret summary")
	rotateCredential := flag.Bool("rotate-credential", false, "Retrieve and acknowledge a pending Agent credential rotation")
	deliveryID := flag.String("delivery-id", "", "Central credential delivery ID to retrieve")
	flag.Parse()

	if *runHandoffBroker {
		if *showVersion || *enroll || *manifestPath != "" || *enrollmentTokenStdin || *enrollmentSummaryStdout || *verifyExistingIdentity || *rotateCredential || *deliveryID != "" {
			fmt.Fprintln(os.Stderr, "--handoff-broker cannot be combined with Agent CLI operations")
			os.Exit(2)
		}

		brokerConfig, err := handoffbroker.LoadConfig(*brokerConfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NADI handoff broker configuration error: %v\n", err)
			os.Exit(1)
		}

		broker, err := handoffbroker.NewServer(*brokerSocketPath, brokerConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NADI handoff broker initialization error: %v\n", err)
			os.Exit(1)
		}

		if err := broker.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "NADI handoff broker stopped: %v\n", err)
			os.Exit(1)
		}

		return
	}

	if *showVersion {
		fmt.Printf("NADI Agent %s\n", version.Agent)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	if *verifyExistingIdentity && (*showVersion || *enroll || *manifestPath != "" || *enrollmentTokenStdin || *enrollmentSummaryStdout || *rotateCredential || *deliveryID != "") {
		fmt.Fprintln(os.Stderr, "--verify-existing-identity-summary-stdout cannot be combined with other Agent operations")
		os.Exit(2)
	}

	if *rotateCredential && (*enroll || *manifestPath != "" || *enrollmentTokenStdin || *enrollmentSummaryStdout || *verifyExistingIdentity) {
		fmt.Fprintln(os.Stderr, "--rotate-credential cannot be combined with Enrollment options")
		os.Exit(2)
	}

	if *rotateCredential && strings.TrimSpace(*deliveryID) == "" {
		fmt.Fprintln(os.Stderr, "--rotate-credential requires --delivery-id")
		os.Exit(2)
	}

	if !*rotateCredential && strings.TrimSpace(*deliveryID) != "" {
		fmt.Fprintln(os.Stderr, "--delivery-id requires --rotate-credential")
		os.Exit(2)
	}

	if *enrollmentTokenStdin && !*enroll {
		fmt.Fprintln(os.Stderr, "--enrollment-token-stdin requires --enroll")
		os.Exit(2)
	}

	if *enrollmentSummaryStdout && !*enroll {
		fmt.Fprintln(os.Stderr, "--enrollment-summary-stdout requires --enroll")
		os.Exit(2)
	}

	if *enrollmentTokenStdin && strings.TrimSpace(cfg.EnrollmentToken) != "" {
		fmt.Fprintln(os.Stderr, "do not combine --enrollment-token-stdin with NADI_ENROLLMENT_TOKEN")
		os.Exit(2)
	}

	if *enrollmentTokenStdin {
		token, readErr := readEnrollmentToken(os.Stdin)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "unable to read Enrollment token from stdin: %v\n", readErr)
			os.Exit(1)
		}

		cfg.EnrollmentToken = token
	}

	logger := logging.New(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	application := app.New(cfg, logger)

	if *verifyExistingIdentity {
		if err := application.WriteVerifiedEnrollmentSummary(os.Stdout); err != nil {
			logger.Error("Existing NADI Agent identity verification failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if *rotateCredential {
		if err := application.RotateCredential(ctx, *deliveryID); err != nil {
			logger.Error("NADI Agent credential rotation did not complete", "error", err)
			os.Exit(1)
		}
		return
	}

	if *enroll {
		if err := application.Enroll(ctx, *manifestPath); err != nil {
			logger.Error("NADI Agent Enrollment failed", "error", err)
			os.Exit(1)
		}

		if *enrollmentSummaryStdout {
			if err := application.WriteEnrollmentSummary(os.Stdout); err != nil {
				logger.Error("Unable to produce non-secret NADI Agent enrollment summary", "error", err)
				os.Exit(1)
			}
		}

		return
	}

	if *manifestPath != "" {
		fmt.Fprintln(os.Stderr, "--manifest requires --enroll")
		os.Exit(2)
	}

	if err := application.Run(ctx); err != nil {
		logger.Error("NADI Agent stopped with an error", "error", err)
		os.Exit(1)
	}
}

func readEnrollmentToken(reader io.Reader) (string, error) {
	tokenBytes, err := io.ReadAll(io.LimitReader(reader, 257))
	if err != nil {
		return "", err
	}

	if len(tokenBytes) > 256 {
		return "", fmt.Errorf("Enrollment token input exceeds the allowed size")
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return "", fmt.Errorf("Enrollment token input is empty")
	}

	return token, nil
}
