{ pkgs, lib, config, inputs, ... }: {
  # Language configuration
  languages.go = {
    enable = true;
    package = pkgs.go_1_21;
  };

  # Package list
  packages = [
    pkgs.just
    pkgs.docker-compose
  ];

  # Scripts
  scripts.validate.exec = "just validate";
  scripts.test.exec = "just test";
  scripts.docker-test.exec = "just docker-test";

  # Welcome message
  enterShell = ''
    echo "====================================================="
    echo "  Welcome to Myrmex Hive Development Environment"
    echo "====================================================="
    echo "Go version: $(go version)"
    echo "Commands available:"
    echo "  - validate: Format and run syntax checks"
    echo "  - test: Run unit tests"
    echo "  - docker-test: Run full integration tests"
    echo "====================================================="
  '';
}
