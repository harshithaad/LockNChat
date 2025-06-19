## Project Overview
•	Team Name: LockNChat
•	Problem Statement: Messaging App with Encrypted Chat — Develop a secure chat system where users can exchange end-to-end encrypted messages. Include secure user authentication, encryption key management, and message expiration.
SecureChat is our solution to the above problem. It is a web-based messaging application that prioritizes user privacy, secure communication, and modern UI/UX practices. The app is developed using React for the frontend and Firebase for backend services like real-time messaging and authentication.
Key Features:
•	User Authentication: Only registered users can log in using Firebase Authentication. Password validation ensures strong credentials.
•	End-to-End Encryption: Messages are encrypted on the sender’s side and decrypted only on the recipient’s side using AES encryption combined with Diffie-Hellman key exchange.
•	Encryption Key Management: Each conversation generates a unique secret key which is never stored on the server.
•	Message Expiration (Planned Feature): While not yet active, the design supports implementing timed message expiration.
•	Security Controls: CAPTCHA, login rate limiting, and input restrictions defend against spam, bots, and injection attacks.
•	Minimalist Design: UI is clean and secure, with routing restricted to / for login/register and /chat for messaging.
SecureChat ensures that users can communicate privately, securely, and in real-time. No sensitive information is stored or shared that could compromise data confidentiality.
________________________________________________________________________________
## Setup Instructions
•	Clone the project:
 	git clone <REPO_URL>
cd EndToEndEncrypted-Chat-app
•	Install required packages:
 	npm install
•	Run the application:
 	set NODE_OPTIONS=--openssl-legacy-provider
 	npm start
•	Open http://localhost:3000/ in your browser
⚠️ Note: The .env file is excluded from the public repository for security. Firebase credentials must be added manually by authorized users.
________________________________________________________________________________
## Usage Instructions
•	Visit / for login or register.
•	Register with a valid email and a strong password.
•	Password rules:
o	Minimum 8 characters
o	At least 1 uppercase and 1 lowercase letter
o	At least 1 number and 1 special character
•	If login fails more than twice, user must wait 1 minute.
•	CAPTCHA is shown after login to verify human access.
•	Navigate to /chat to send and receive encrypted messages.
________________________________________________________________________________
## Dependencies
•	react: For building the frontend UI
•	firebase: For authentication and real-time data
•	crypto-js: For AES encryption/decryption
•	uuid: For generating unique identifiers
Dependencies are listed in package.json and are installed using npm install.
________________________________________________________________________________
## Environment Configuration
A .env file must be created with Firebase project configuration. This file is not included in the public repo.
REACT_APP_FIREBASE_API_KEY=your_api_key
REACT_APP_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your_project_id
REACT_APP_FIREBASE_STORAGE_BUCKET=your_project_id.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=sender_id
REACT_APP_FIREBASE_APP_ID=app_id
>This file must be managed securely and not shared publicly.
________________________________________________________________________________
## Code Comments
•	Inline comments are added to explain complex logic such as:
o	Login flow
o	Encryption/decryption processes
o	CAPTCHA logic
o	Rate limiting and validation
Comments do not reveal any keys or sensitive logic paths.
________________________________________________________________________________
## API Documentation
SecureChat uses Firebase services; no custom backend APIs are implemented. It interacts with:
•	Firebase Auth: For user registration and login
•	Firebase Firestore: For encrypted message storage
•	All encryption occurs on the client side; the server never sees plain text.
________________________________________________________________________________
## License
•	The project is covered under the MIT License.
•	License file is included in the root folder.
________________________________________________________________________________
## Contribution Guide
How to contribute:
1.	Fork the repository
2.	Clone it locally
3.	Create a new feature branch
4.	Make changes and commit
5.	Push to your fork
6.	Open a pull request
Guidelines:
•	Follow coding style and structure
•	Add clear comments for complex logic
•	Do not hardcode secrets or sensitive details
