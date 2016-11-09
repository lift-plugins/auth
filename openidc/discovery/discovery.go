package discovery

// Run downloads provider configuration, signing keys and store those to disk.
func Run(address string) error {
	config := new(ProviderConfig)
	if err := config.Fetch(address); err != nil {
		return err
	}

	if err := config.Write(); err != nil {
		return err
	}

	keys := new(SigningKeys)
	if err := keys.Fetch(config.JWKSURI); err != nil {
		return err
	}

	if err := keys.Write(); err != nil {
		return err
	}
	return nil
}
