import { createUserWithEmailAndPassword, signInWithEmailAndPassword } from '@firebase/auth';
import { getDoc, setDoc, doc } from '@firebase/firestore';
import React, { useRef, useState, useEffect } from 'react';
import { useHistory } from 'react-router-dom';
import { db, auth } from '../../firebase';
import './login-screen.css';

const getSafeRedirect = (urlParam) => {
  const allowedRoutes = ["/chat"];
  return allowedRoutes.includes(urlParam) ? urlParam : "/chat";
};

export default function LoginScreen({ setUser }) {
  const [attempts, setAttempts] = useState(0);
  const [locked, setLocked] = useState(false);
  const captchaRef = useRef(null); // <== ADD THIS LINE


  let history = useHistory();

  const Crypto = require('crypto');
  var generator = 0;
  var prime = 0;

  const email = useRef(null);
  const password = useRef(null);

  const isCaptchaVerified = () => {
    const response = window.grecaptcha.getResponse();
    return response.length !== 0;
  };

  const isStrongPassword = (pwd) => {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/;
    return regex.test(pwd);
  };

  const register = async () => {
    const myEmail = email.current.value;
    const myPassword = password.current.value;

    if (!isCaptchaVerified()) {
      alert('Please complete the CAPTCHA.');
      return;
    }

    if (!isStrongPassword(myPassword)) {
      alert('Password must be at least 8 characters long and include a number, uppercase, lowercase, and special character.');
      return;
    }

    try {
      const responseFromAuth = await createUserWithEmailAndPassword(auth, myEmail, myPassword);
      const userId = responseFromAuth.user.uid;

      const dhRef = doc(db, 'dhparameters', 'dh');
      const docSnap = await getDoc(dhRef);

      if (docSnap.exists()) {
        const docData = docSnap.data();
        generator = docData.generator;
        prime = docData.prime;
      }

      const privkey = randomint(5, generator - 1);
      const pubkey = power(generator, privkey, prime);

      await setDoc(doc(db, 'users', userId), {
        email: myEmail,
        uid: userId,
        privkey: privkey,
        pubkey: pubkey,
      });

      localStorage.setItem('user', JSON.stringify({ email: myEmail, uid: userId }));
      setUser({ email: myEmail, uid: userId });

      window.grecaptcha.reset();

      const params = new URLSearchParams(window.location.search);
      const redirectTo = getSafeRedirect(params.get("redirect"));
      history.push(redirectTo);

    } catch (error) {
      alert(error);
    }
  };

  const login = async () => {
    const myEmail = email.current.value;
    const myPassword = password.current.value;

    if (!isCaptchaVerified()) {
      alert('Please complete the CAPTCHA.');
      return;
    }

    if (locked) {
      alert('Too many failed attempts. PLease try again later!');
      return;
    }

    try {
      const responseFromAuth = await signInWithEmailAndPassword(auth, myEmail, myPassword);
      const userId = responseFromAuth.user.uid;

      localStorage.setItem('user', JSON.stringify({ email: myEmail, uid: userId }));
      setUser({ email: myEmail, uid: userId });

      window.grecaptcha.reset();

      setAttempts(0);
      
      const params = new URLSearchParams(window.location.search);
      const redirectTo = getSafeRedirect(params.get("redirect"));
      history.push(redirectTo);


    } catch (error) {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      alert(`Attempt ${newAttempts}. Login failed.`);

      if (newAttempts >= 2) {
        setLocked(true);
        alert('Too many failed attempts. Please try again later!');
        setTimeout(() => {
          setAttempts(0);
          setLocked(false);
        }, 60000);
      }
    }
  };

  useEffect(() => {
    const user = JSON.parse(localStorage.getItem('user'));
    if (user) {
      setUser(user);
      history.push('/chat');
    }

    if (window.grecaptcha && captchaRef.current) {
    window.grecaptcha.render(captchaRef.current, {
      sitekey: "6Lc7fmUrAAAAAMyblDK3RvEcfBYzDFknu7qfk2TW"
    });
    }

    if (user) {
    setUser(user);
    history.push('/chat');
    }

    
  }, [history, setUser]);

  return (
    <div className='login-screen'>
      <div className='title'>
        <p className='title'>Login Screen</p><br />
      </div>

      <div className='mail'>
        <h3 className='input'>&emsp;&ensp;Email: <input ref={email} /></h3>
      </div>

      <div className='password'>
        <h3 className='input'>Password:  <input type='password' ref={password} /></h3>
      </div>

      <div className='buttongrp'>
        <button className='button' onClick={register}>Register</button>&ensp;
        <button className='button' onClick={login}>Log in</button>
      </div>

      <div className="captcha">
        <div ref={captchaRef}></div>
    </div>
     
     <div className="captcha-container">
     <div ref={captchaRef}></div>
    </div>
</div>
  );
}

function randomint(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

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
