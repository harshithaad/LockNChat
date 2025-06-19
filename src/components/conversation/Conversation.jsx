import React, { useRef, useState, useEffect } from "react";
import { doc, getDoc, updateDoc, setDoc, onSnapshot } from "firebase/firestore";
import { db } from "../../firebase";
import "./conversation.css";

function escapeHTML(str) {
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
}

function sanitizeInput(str) {
  if (typeof str !== "string") return "";
  const trimmed = str.trim().substring(0, 100);
  return trimmed.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
}

export default function Conversation({ receiver, user }) {
  const [conversationId, setConversationId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [secretKey, setSecretKey] = useState("");
  const [dhprime, setDhPrime] = useState("");
  const [dhgenerator, setDhGenerator] = useState("");

  const currentMessage = useRef(null);
  const chatBodyRef = useRef(null);
  const CryptoJS = require("crypto-js");

  const sendMessage = async () => {
    const rawMessage = currentMessage.current.value?.trim();
    if (!rawMessage) return;

    const safeMessage = sanitizeInput(rawMessage);
    const sharedsecret = secretKey.toString();
    const ciphertext = CryptoJS.AES.encrypt(safeMessage, sharedsecret).toString();

    const myMessage = {
      message: ciphertext,
      uid: user.uid,
      timestamp: Date.now(), // Timestamp for expiration
    };

    const conversationRef = doc(db, "conversations", conversationId);
    const docSnap = await getDoc(conversationRef);

    if (docSnap.exists()) {
      const docData = docSnap.data();
      const freshMessages = docData.messages.filter((m) => Date.now() - m.timestamp <= 30000); // 30 seconds
      await updateDoc(conversationRef, {
        messages: [...freshMessages, myMessage],
      });
    } else {
      await setDoc(conversationRef, {
        messages: [myMessage],
      });
    }

    currentMessage.current.value = "";
  };

  const setUpSecretKey = async () => {
    if (!receiver || !user) return;

    const dhRef = doc(db, "dhparameters", "dh");
    const dhSnap = await getDoc(dhRef);
    if (dhSnap.exists()) {
      const dhData = dhSnap.data();
      setDhPrime(dhData.prime);
      setDhGenerator(dhData.generator);
    }

    const senderRef = doc(db, "users", user.uid);
    const senderSnap = await getDoc(senderRef);
    const senderData = senderSnap.data();
    const senderPriv = senderData.privkey;

    const receiverRef = doc(db, "users", receiver.uid);
    const receiverSnap = await getDoc(receiverRef);
    const receiverData = receiverSnap.data();
    const receiverPub = receiverData.pubkey;

    const shared = power(receiverPub, senderPriv, dhprime);
    setSecretKey(shared);

    const id = receiver.uid > user.uid ? receiver.uid + user.uid : user.uid + receiver.uid;
    setConversationId(id);
  };

  useEffect(() => {
    setUpSecretKey();
  }, [receiver, user]);

  useEffect(() => {
    if (!conversationId || !secretKey) return;

    const sharedsecret = secretKey.toString();
    const unsub = onSnapshot(doc(db, "conversations", conversationId), (doc) => {
      const data = doc.data();
      if (!data?.messages) return setMessages([]);

      const decryptedMessages = data.messages
        .filter((m) => Date.now() - m.timestamp <= 60000) // 60 seconds
        .map((m) => {
          try {
            const bytes = CryptoJS.AES.decrypt(m.message, sharedsecret);
            const plaintext = bytes.toString(CryptoJS.enc.Utf8);
            return { ...m, message: plaintext };
          } catch {
            return { ...m, message: "[DECRYPTION FAILED]" };
          }
        });

      setMessages(decryptedMessages);
    });

    return unsub;
  }, [conversationId, secretKey]);

  useEffect(() => {
    if (!chatBodyRef.current) return;
    chatBodyRef.current.scrollTop = chatBodyRef.current.scrollHeight;
  }, [messages]);

  useEffect(() => {
    const interval = setInterval(() => {
      setMessages((prev) =>
        prev.filter((m) => Date.now() - m.timestamp <= 30000)
      );
    }, 5000); // Check every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const handleEnterKeyPressDown = (e) => {
    if ((e.key === "Enter" || e.code === "Enter") && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
  <div className="chatscreen">
    {receiver ? (
      <>
        <div className="chat">
          {/* Chat title */}
          <p title={receiver.email} className="receiver">
            Conversation with {receiver.email}
          </p>

          {/* Message list */}
          <div className="conversation-messages" ref={chatBodyRef}>
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className="message-container"
                style={{
                  justifyContent:
                    msg.uid === user.uid ? "flex-end" : "flex-start",
                }}
              >
                <div className="message-content">
                  {escapeHTML(msg.message)}
                </div>
              </div>
            ))}
          </div>

          {/* Input area */}
          <div className="input-container">
            <div className="input-message">
              <input
                placeholder="Enter message"
                ref={currentMessage}
                onKeyDown={handleEnterKeyPressDown}
              />
            </div>
            <button onClick={sendMessage}>Go</button>
          </div>
        </div>

        {/* Encryption Sidebar */}
        <div className="encryption-elements">
          <h3>🔒 Encrypted Chat</h3>
          <p>Your messages are end-to-end encrypted.</p>
          <p>⏳ Expiry in: <span id="expiry-timer">60</span> seconds</p>
        </div>
      </>
    ) : (
      <div className="nochat">
        <p>Pick someone to talk to.</p>
      </div>
    )}
  </div>
);

}

// Modular exponentiation
function power(a, b, p) {
  let res = 0;
  a = a % p;
  while (b > 0) {
    if (b % 2 === 1) {
      res = (res + a) % p;
    }
    a = (a * 2) % p;
    b = Math.floor(b / 2);
  }
  return res % p;
}