// Package profile implements profile parsing
//
// It requires env.PROFILES_DIRECTORY environment variable to be set before initialization phase.
// Value from this variable establishes non-mutable entrypoint directory for profiles.

// To load profiles from a file use [LoadProfiles] func.
// When desired set of profiles is loaded, you can retrieve any by name using [Retrieve].
// [Profile] is structure that represents parsed & validated profile ready to use.

// The raw profile implements a struct that reads the profile from the YAML file.
// This profile is then for convienience slightly adapted to another struct, called
// Profile, which will be used internally by the server
package profile
