# Document Repository

**Authors:**
- [Alexandre Regalado](https://github.com/Alxit0)
- [Bernardo Borges](https://github.com/BennyTime)
- [António Moreira](https://github.com/AntonioMSPMoreira13)

**Course:** Security of Information and Organizations

## 📜 Description

This project was developed as part of the Security course at University of Aveiro. Its primary focus is to demonstrate the implementation of fundamental security concepts and technologies in a practical application. The project showcases how to design and develop a secure system while adhering to modern cybersecurity best practices.

The core objectives of this project include:

- Implementing secure communication mechanisms.
- Protecting sensitive data using robust encryption algorithms.
- Ensuring user authentication and access control.
- Identifying and mitigating potential vulnerabilities.

This repository contains the source code, documentation, and examples needed to understand and utilize the project effectively. It is designed to provide hands-on experience in applying theoretical security concepts to real-world problems.

> [Project Guide](./guide.md)

## 🛠️ Technologies Used

- **Programming Language(s):** python3, bash  
- **Framework(s) and Library/Libraries:** Flask, sqlite3, cryptography, hashlib, jwt, click

## 📂 Folder Structure

```plaintext
├── delivery?/           # Code for each step of development
├── delivery3/           # Documentation and analasys
├── src/                 # Source code
│   ├── api/             # Server side aplication
│   ├── cli/             # Client sied aplication commands
│   ├── tests/           # Tests for the project
├── README.md            # This file
```

## 🚀 Getting Started

Follow these instructions to set up and run the project on your local machine.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Alxit0/document-repo-service.git
   cd document-repo-service
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the project:
   ```bash
   cd src/api
   python app.py
   ```

### Usage

1. Go to commands directory
    ```bash
    cd src/cli
    ```

2. Set up client
    ```bash
    ./rep_subject_credentials -k <public key of server> -r <repo ip> <password> <creds file>
    ```

3. Run any commands following the required syntax
    ```bash
    ./rep_* arg1 arg2 ...
    ```

## 📖 Documentation

- **ASVS analasys:** [ASVS](./delivery3/asvs-acess-control.md)
- **Project Report:** [Report](./delivery3/Relatório_SIO.pdf)

## 📝 License

This project is licensed under the [LICENSE NAME] - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

Special thanks to Professor [João Paulo Barraca](https://github.com/jpbarraca) for guidance and feedback.

## 🛡️ Security Considerations

This project is for educational purposes and is not intended for production use.
