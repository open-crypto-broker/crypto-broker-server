package profile

import (
	"errors"
	"fmt"
	"io"
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

// init sets profilesRootDir variable. Throws an error if the provided path is not absolute or it cannot be opened.
// As per Golang convention, init function is called automatically before main function when the package is imported.
func init() {
	profilesDirFullOSPath := os.Getenv(env.PROFILES_DIRECTORY)
	if !path.IsAbs(profilesDirFullOSPath) {
		panic(fmt.Sprintf("please provide full OS path to profiles directory through %s environment variable", env.PROFILES_DIRECTORY))
	}
	root, err := os.OpenRoot(profilesDirFullOSPath)
	if err != nil {
		panic(fmt.Errorf("could not open dir: %s, err: %w", profilesDirFullOSPath, err))
	}

	profilesRootDir = root
}

// LoadProfiles parses & validates YAML formatted profiles from provided file.
// Internally function
//   - sets value of package global variable that holds such profiles
//   - validates each profile, if any of them contains error, func returns it
func LoadProfiles(profilesFileName string) error {
	profileFile, err := profilesRootDir.Open(profilesFileName)
	if err != nil {
		return fmt.Errorf("could not open file: %s, err: %w", profilesFileName, err)
	}

	profileBytes, err := io.ReadAll(profileFile)
	if err != nil {
		return fmt.Errorf("could not read profile content, err: %w", err)
	}

	var rawProfiles []rawProfile
	if err = yaml.Unmarshal(profileBytes, &rawProfiles); err != nil {
		return fmt.Errorf("could not unmarshal YAML profile, err: %w", err)
	}

	if profiles, err = convertRawProfilesData(rawProfiles); err != nil {
		return err
	}

	return nil
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
