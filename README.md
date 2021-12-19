# Dependencies - A port of the Dependencies app by lucasg to the Windows App SDK

This is a port of Dependencies (https://github.com/lucasg/Dependencies/) to the Windows App SDK. Most features have been ported over from the original WPF based application.

The windowsappsdk branch contains the ported GUI application while the windowsappsdk_arm64 branch also contains an updated phlib, allowing native execution on arm64 based systems.

## Installation and Usage

Select the DependenciesWAS project as the start project. Select the Debug or Release solution configuration in combination with the "Dependencies WAS (Unpackaged)" launch configuration. Alternatively, select the Packaged solution configuration in combination with the "Dependencies WAS (Packaged)" launch configuration to build and run an MSIX package.
