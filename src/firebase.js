//Setting firebase for our chat-app
// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import {getAuth} from "firebase/auth";
import {getFirestore} from "firebase/firestore";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBQVjbGtt83Um74VdU7qfJuGZF4FoQZjpo",
  authDomain: "chat-app-56d6e.firebaseapp.com",
  projectId: "chat-app-56d6e",
  storageBucket: "chat-app-56d6e.firebasestorage.app",
  messagingSenderId: "1056163662157",
  appId: "1:1056163662157:web:3024aa8ce70fe300e50f04",
  measurementId: "G-RFKX523V91"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

const db = getFirestore();
const auth = getAuth();

export {auth, db};