package profile

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"

	"github.com/goccy/go-yaml"
)

// profilesRootDir profiles directory set during pkg initialization
var profilesRootDir *os.Root

// profiles represents map of parsed profiles. Key is profile name.
// Its nil until successful invocation of LoadProfiles function.
var profiles map[string]Profile

// settingsConfiguration is shared by all profiles.
var settingsConfiguration SettingsConfiguration

// kmsConfiguration is shared by all profiles.
var kmsConfiguration KMSConfiguration

// init sets profilesRootDir variable. Throws an error if the provided path is not absolute or it cannot be opened.
// As per Golang convention, init function is called automatically before main function when the package is imported.
func init() {
	profilesDirFullOSPath := os.Getenv(env.PROFILES_DIRECTORY)
	if !path.IsAbs(profilesDirFullOSPath) {
		slog.Debug(fmt.Sprintf("please provide full OS path to profiles directory through %s environment variable", env.PROFILES_DIRECTORY))

		panic(fmt.Sprintf("please provide full OS path to profiles directory through %s environment variable", env.PROFILES_DIRECTORY))
	}
	root, err := os.OpenRoot(profilesDirFullOSPath)
	if err != nil {
		// #nosec G706 - Debug should handle sanitization
		slog.Debug("could not open dir",
			"path", profilesDirFullOSPath,
			"error", err,
		)

		panic(fmt.Errorf("could not open dir: %s, err: %w", profilesDirFullOSPath, err))
	}

	profilesRootDir = root
}

// LoadProfiles parses and validates the shared settings, KMS configuration,
// and profiles from the provided YAML file.
func LoadProfiles(profilesFileName string) error {
	profileFile, err := profilesRootDir.Open(profilesFileName)
	if err != nil {
		return fmt.Errorf("could not open file: %s, err: %w", profilesFileName, err)
	}

	profileBytes, err := io.ReadAll(profileFile)
	if err != nil {
		return fmt.Errorf("could not read profile content, err: %w", err)
	}

	var rawConfig rawProfilesConfig
	if err = yaml.Unmarshal(profileBytes, &rawConfig); err != nil {
		return fmt.Errorf("could not unmarshal YAML profile, err: %w", err)
	}

	if err = rawConfig.Settings.validate(); err != nil {
		return fmt.Errorf("could not parse settings, err: %w", err)
	}

	parsedProfiles, err := convertRawProfilesData(rawConfig.Profiles)
	if err != nil {
		return err
	}

	profiles = parsedProfiles
	settingsConfiguration = rawConfig.Settings.configuration()
	kmsConfiguration = KMSConfiguration{
		Client: rawConfig.KMS.Client,
		Config: rawConfig.KMS.Config,
		Cache:  rawConfig.KMS.Cache,
	}

	return nil
}

// Settings returns the configuration shared by all profiles.
func Settings() SettingsConfiguration {
	return settingsConfiguration
}

// KMS returns the KMS configuration shared by all profiles.
func KMS() KMSConfiguration {
	return kmsConfiguration
}

// Profiles returns a copy of all configured profiles indexed by name.
func Profiles() map[string]Profile {
	configuredProfiles := make(map[string]Profile, len(profiles))
	for name, configuredProfile := range profiles {
		configuredProfiles[name] = configuredProfile
	}

	return configuredProfiles
}

func convertRawProfilesData(rawProfiles []rawProfile) (map[string]Profile, error) {
	finalProfiles := make(map[string]Profile, len(rawProfiles))
	var err error
	for _, rp := range rawProfiles {
		p, errConversion := rp.mapToProfile()
		if errConversion != nil {
			err = errors.Join(err, fmt.Errorf("could not parse profile: %s, err: %w", rp.Name, errConversion))

			continue
		}

		if _, ok := finalProfiles[p.Name]; ok {
			return nil, fmt.Errorf("duplicate profile name: %s", p.Name)
		}

		finalProfiles[p.Name] = p
	}

	if err != nil {
		return nil, err
	}

	return finalProfiles, nil
}

// Retrieve returns Profile by its name or returns non-nil error if any
func Retrieve(name string) (Profile, error) {
	if len(profiles) == 0 {
		return Profile{}, fmt.Errorf("please load profiles before retrieving one of them")
	}

	p, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("there is no profile: %s", name)
	}

	return p, nil
}
