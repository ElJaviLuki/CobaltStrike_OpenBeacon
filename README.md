# Cobalt Strike Beacon Open Source Implementation

## Overview

Welcome to the open-source implementation of the Cobalt Strike Beacon! This project aims to provide a fully functional, from-scratch alternative to the Cobalt Strike Beacon, offering transparency and flexibility for security professionals and enthusiasts.

Please note that this project is not a reverse-engineered version of the Cobalt Strike Beacon but a ground-up open-source implementation. The `settings.h` file, containing macros for the C2 Profile, is .gitignored (and thus not available), as users are expected to complete it according to their preferences. Once you have your `settings.h` template ready, feel free to share and contribute.

## Prerequisites

- Visual Studio: The project is built using Visual Studio, not Visual Studio Code.
- [libtommath](https://github.com/libtom/libtommath): A fast, portable number-theoretic multiple-precision integer library.
- [libtomcrypt](https://github.com/libtom/libtomcrypt): A modular and portable cryptographic toolkit.

## Getting Started

1. Clone the repository:

    ```bash
    git clone https://github.com/ElJaviLuki/CobaltStrike_Beacon.git
    ```

2. Open the project in Visual Studio.

3. Ensure that the required dependencies (libtommath, libtomcrypt) are properly configured and linked with the project.

4. Build the project.

5. Create your `settings.h` file based on the provided template. Make sure to include your C2 Profile macros and configurations.

6. Build the project again to apply your custom settings.

7. Execute the compiled binary.

## Contributing

We welcome contributions from the community. If you have improvements, bug fixes, or new features to add, please submit a pull request. Be sure to follow the existing coding style and provide clear commit messages.

## License

This project is licensed under the [MIT License](LICENSE.md).

## Disclaimer

This project is for educational and research purposes only. Use it responsibly and in compliance with applicable laws and regulations. The authors and contributors are not responsible for any misuse or damage caused by the use of this software.
