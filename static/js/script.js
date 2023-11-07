function register() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const captcha = document.getElementById('captcha').value;

  let passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*?[#?!@$%^&*-]).{8,}$/;
  if (!passwordRegex.test(password)) {
    alert('密码包括大小写字母，数字和特殊字符，8位以上');
    return;
  }

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, captcha }; // Include the user and hashed password
      fetch('/registuser', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
          // First, check if the response status is not OK (not 2xx).
          if (!response.ok) {
              // If not OK, try to parse the JSON.
              return response.json().then(data => {
                  throw new Error(data.message); // Use the message from the server as the error message.
              });
          }
          return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          alert('注册成功');
          // redirect to login page
          const qrCodeBase64 = data.qrcode;
          // 创建一个新的Image元素
          const image = new Image();
          image.src = qrCodeBase64;
      
          // 将图片添加到页面中某个元素内
          document.getElementById('qrCodeContainer').appendChild(image);
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}


function login() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const recaptchaResponse = grecaptcha.getResponse();
  const otp = document.getElementById('otp').value;

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, recaptchaResponse, otp }; // Include the user and hashed password
      fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        // First, check if the response status is not OK (not 2xx).
        if (!response.ok) {
            // If not OK, try to parse the JSON.
            return response.json().then(data => {
                throw new Error(data.message); // Use the message from the server as the error message.
            });
        }
        return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          alert('登录成功');
          window.location.href = 'https://www.example.com/'; 
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}

function login_otp() {
  const user = document.getElementById('user').value;
  const hashedPassword = document.getElementById('password').value;
  const recaptchaResponse = grecaptcha.getResponse();

  // login directly, no need to hash password
  const data = { user, hashedPassword, recaptchaResponse }; // Include the user and hashed password
  fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  }) 
  .then(response => {
    // First, check if the response status is not OK (not 2xx).
    if (!response.ok) {
        // If not OK, try to parse the JSON.
        return response.json().then(data => {
            throw new Error(data.message); // Use the message from the server as the error message.
        });
    }
    return response.json(); // If everything is OK, continue to process the data.
  })
  .then(data => {
      // Handle your successful data here, if needed.
      alert('登录成功');
      window.location.href = 'https://www.example.com/'; 
  })
  .catch(error => {
      // Display the error message as an alert.
      alert(error.message);
  });
}

function resetpasswd() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const captcha = document.getElementById('captcha').value;

  let passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*?[#?!@$%^&*-]).{8,}$/;
  if (!passwordRegex.test(password)) {
    alert('密码包括大小写字母，数字和特殊字符，8位以上');
    return;
  }

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, captcha }; // Include the user and hashed password
      fetch('/resetpasswd', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        // First, check if the response status is not OK (not 2xx).
        if (!response.ok) {
            // If not OK, try to parse the JSON.
            return response.json().then(data => {
                throw new Error(data.message); // Use the message from the server as the error message.
            });
        }
        return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          alert('重置密码成功');
          // redirect to login page
          window.location.href = '/';
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}

function sendVerification() {
  const email = document.getElementById('user').value;
  const responseMessage = document.getElementById('responseMessage');
  const recaptchaResponse = grecaptcha.getResponse();

  const data = { email, recaptchaResponse }; // Include the user and hashed password  
  fetch('/send_verification', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
      },
      body: JSON.stringify(data)
  })
  .then(response => {
    // First, check if the response status is not OK (not 2xx).
    if (!response.ok) {
        // If not OK, try to parse the JSON.
        return response.json().then(data => {
            throw new Error(data.message); // Use the message from the server as the error message.
        });
    }
    return response.json(); // If everything is OK, continue to process the data.
  })
  .then(data => {
      // Handle your successful data here, if needed.
      alert('验证码已发送');
  })
  .catch(error => {
      // Display the error message as an alert.
      alert(error.message);
  });
}
