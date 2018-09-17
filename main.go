package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/genuinetools/amicontained/version"
	"github.com/genuinetools/pkg/cli"
	"github.com/jessfraz/bpfd/proc"
	"github.com/sirupsen/logrus"
)

var (
	debug bool
)

func main() {
	// Create a new cli program.
	p := cli.NewProgram()
	p.Name = "amicontained"
	p.Description = "A container introspection tool"

	// Set the GitCommit and Version.
	p.GitCommit = version.GITCOMMIT
	p.Version = version.VERSION

	// Setup the global flags.
	p.FlagSet = flag.NewFlagSet("ship", flag.ExitOnError)
	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		return nil
	}

	// Set the main program action.
	p.Action = func(ctx context.Context, args []string) error {
		// Container Runtime
		runtime := proc.GetContainerRuntime(0, 0)
		fmt.Printf("Container Runtime: %s\n", runtime)

		// Namespaces
		namespaces := []string{"pid"}
		fmt.Println("Has Namespaces:")
		for _, namespace := range namespaces {
			ns, err := proc.HasNamespace(namespace)
			if err != nil {
				fmt.Printf("\t%s: error -> %v\n", namespace, err)
				continue
			}
			fmt.Printf("\t%s: %t\n", namespace, ns)
		}

		// User Namespaces
		userNS, userMappings := proc.GetUserNamespaceInfo(0)
		fmt.Printf("\tuser: %t\n", userNS)
		if len(userMappings) > 0 {
			fmt.Println("User Namespace Mappings:")
			for _, userMapping := range userMappings {
				fmt.Printf("\tContainer -> %d\tHost -> %d\tRange -> %d\n", userMapping.ContainerID, userMapping.HostID, userMapping.Range)
			}
		}

		// AppArmor Profile
		aaprof := proc.GetAppArmorProfile(0)
		fmt.Printf("AppArmor Profile: %s\n", aaprof)

		// Capabilities
		caps, err := proc.GetCapabilities(0)
		if err != nil {
			logrus.Warnf("getting capabilities failed: %v", err)
		}
		if len(caps) > 0 {
			fmt.Println("Capabilities:")
			for k, v := range caps {
				if len(v) > 0 {
					fmt.Printf("\t%s -> %s\n", k, strings.Join(v, " "))
				}
			}
		}

		// Seccomp
		seccompMode := proc.GetSeccompEnforcingMode(0)
		fmt.Printf("Seccomp: %s\n", seccompMode)

		return nil
	}

	// Run our program.
	p.Run()
}
