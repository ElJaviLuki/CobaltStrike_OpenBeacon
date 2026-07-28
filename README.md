# Cobalt Strike Beacon Open Source Implementation

> ## 👨‍💻 About the Author & Open to Opportunities
>
> I never expected that a project I started so naively from the comfort of my country house would catch the attention of professionals from Big Tech (Google, Atlassian, Alibaba, KPMG, HSBC), Cybersecurity firms (SpecterOps, MISP, CIRCL, CVE-Search, Cirosec, Picus Security, Bad Sector Labs, illics-intel Offensive Security, SixGen), Governments (Italian Ministry of Defense), and Universities (Peking, Nanjing, Patras, BLCU, etc.). 
> 
> Seeing this level of interest has been incredibly humbling and motivating. Because of this, I am currently expanding my career and I am **actively looking for new professional opportunities and academic collaborations.**
> 
> * **For Companies (Red Team / Cybersecurity / Dev):** I am open to job offers, internships, or freelance contracting. If my work on this project aligns with your team's needs, I'd love to chat.
> * **For Universities & Researchers:** I am highly interested in joining a university program, research lab, or academic group to further develop my skills and contribute to formal research.
> 
> 📫 **How to reach me:**
> * Email: eljaviluki@gmail.com
> * LinkedIn: https://www.linkedin.com/in/eljaviluki

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
    git clone https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon.git
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
